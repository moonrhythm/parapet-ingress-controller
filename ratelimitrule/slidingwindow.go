package ratelimitrule

import (
	"sync"
	"time"
)

// slidingWindowStrategy implements the sliding-window-counter algorithm with
// the same admit/After math as parapet's ratelimit.SlidingWindowStrategy (keep
// the two in semantic lockstep), but with different storage. It originally
// existed because parapet's janitor goroutine could never be stopped and would
// leak per SetLimits rebuild — fixed upstream in v0.18.1 (parapet#243). The
// fork is RETAINED for what remains deliberately different here: NO background
// goroutine at all, O(1) whole-generation eviction instead of per-entry sweeps
// under the lock, and the stricter backward-clock semantics below (parapet's
// roll still regresses the per-item window index). Dropping the fork for
// parapet's strategy is possible but would trade those away — see
// RATELIMIT.md.
//
// Storage is two whole-window generations: cur counts the current fixed window,
// prev the one before it. Crossing a boundary retires a full generation at once
// (a map swap/clear, O(1) amortized — no per-entry sweep on anyone's request
// path), so the working set is bounded to keys seen in the last ~2 windows,
// like parapet's swept map. The trade-off is idle retention: a limiter that
// stops receiving Takes holds its last two generations until the next Take or
// until the whole strategy is dropped (zone deleted / limit reconfigured) —
// bounded in size, unbounded in time, and accepted to stay goroutine-free.
//
// Like parapet's, the blend is an APPROXIMATION (assumes the previous window's
// requests were uniform in time; error typically under ~1% of Rate) and window
// indices ride the wall clock. A backward clock step never regresses the
// generations here (backward-time Takes simply count into the current one) —
// deliberately stricter than parapet, whose per-item roll adopts the earlier
// window index and forgets up to one window of counts when the clock recovers.
type slidingWindowStrategy struct {
	mu     sync.Mutex
	window int64          // fixed-window index that cur counts
	cur    map[string]int // counts in window
	prev   map[string]int // counts in window-1

	max  int
	size int64        // window size in ns, > 0 (validated by SetLimits)
	now  func() int64 // test hook returning ns since epoch; nil = wall clock
}

func newSlidingWindow(rate int, window time.Duration) *slidingWindowStrategy {
	return &slidingWindowStrategy{
		max:  rate,
		size: int64(window),
		cur:  map[string]int{},
		prev: map[string]int{},
	}
}

// nowNano returns the current time in ns since epoch, via the test hook when set.
func (s *slidingWindowStrategy) nowNano() int64 {
	if s.now != nil {
		return s.now()
	}
	return time.Now().UnixNano()
}

// roll advances the generations to currentWindow. Caller holds mu. One
// boundary shifts cur into prev and recycles the retired prev map (cleared, so
// its buckets are reused instead of reallocated each boundary — same trick as
// parapet's FixedWindowStrategy); a larger gap clears both.
//
// d <= 0 (same window, or a backward clock step) is a TRUE no-op: s.window is
// pinned at its high-water value. This deliberately diverges from parapet's
// roll, which unconditionally adopts currentWindow — regressing the per-item
// index on a backward step so the recovery Take re-shifts curr->prev and
// forgets up to one window of real counts (over-admission). Do not "fix" this
// back into lockstep; TestSlidingWindow_BackwardClock* pin the behavior.
func (s *slidingWindowStrategy) roll(currentWindow int64) {
	switch d := currentWindow - s.window; {
	case d <= 0:
		return
	case d == 1:
		retired := s.prev
		clear(retired)
		s.prev, s.cur = s.cur, retired
	default:
		clear(s.cur)
		clear(s.prev)
	}
	s.window = currentWindow
}

// Take admits a request iff the weighted trailing-window count stays within
// max. max <= 0 admits nothing (unreachable via SetLimits, which requires
// rate > 0; kept for parity with parapet).
func (s *slidingWindowStrategy) Take(key string) bool {
	now := s.nowNano()
	currentWindow := now / s.size

	s.mu.Lock()
	defer s.mu.Unlock()

	s.roll(currentWindow)
	prev, cur := s.prev[key], s.cur[key]
	if weightedCount(prev, cur, now, s.size)+1 > float64(s.max) {
		return false
	}
	s.cur[key] = cur + 1
	return true
}

// Put does nothing — this is an arrival-rate limiter, not a concurrency limiter.
func (s *slidingWindowStrategy) Put(string) {}

// After returns how long until the next request for key would be admitted. It
// never mutates state: the roll is computed read-only on locals. Like parapet's
// After it can return 0 right after a blocked Take if a boundary fell between
// the calls — the client genuinely can take now.
func (s *slidingWindowStrategy) After(key string) time.Duration {
	now := s.nowNano()
	currentWindow := now / s.size

	s.mu.Lock()
	defer s.mu.Unlock()

	var prev, cur int
	switch d := currentWindow - s.window; {
	case d <= 0:
		prev, cur = s.prev[key], s.cur[key]
	case d == 1:
		prev, cur = s.cur[key], 0
	default:
		// both generations are stale; budget is free
	}
	return afterAt(s.max, prev, cur, s.size, now)
}

// weightedCount returns the time-weighted effective count at now (ns since
// epoch): the previous window's count linearly faded out as the current window
// elapses. Ported from parapet/pkg/ratelimit — keep in lockstep.
func weightedCount(prev, cur int, now, size int64) float64 {
	elapsed := float64(now%size) / float64(size) // fraction [0,1) of current window gone
	return float64(prev)*(1-elapsed) + float64(cur)
}

// afterAt computes the wait until the next admit for a key already rolled to
// (prev, cur) at time now (ns), with window size size (> 0). Pure — no shared
// state, no clock — and never too optimistic: at now+afterAt the request is
// admissible, so a client honoring Retry-After does not retry into another
// denial. Ported from parapet/pkg/ratelimit's afterAt — keep in lockstep.
func afterAt(maxTokens, prev, cur int, size, now int64) time.Duration {
	if weightedCount(prev, cur, now, size)+1 <= float64(maxTokens) {
		return 0 // can take now
	}

	curFrac := float64(now%size) / float64(size)
	toBoundary := time.Duration((now/size+1)*size - now)

	// Relief within THIS window: prev decays. Possible only while cur alone is
	// under the limit and prev is actually decaying. Solve
	// prev*(1-frac) + cur + 1 == maxTokens.
	if prev > 0 && cur+1 <= maxTokens {
		targetFrac := 1 - (float64(maxTokens)-float64(cur)-1)/float64(prev)
		if targetFrac > curFrac && targetFrac < 1 {
			return time.Duration((targetFrac-curFrac)*float64(size)) + 1 // +1ns: never report 0 while blocked
		}
	}

	// Relief at/after the next boundary, where cur becomes the new prev.
	if cur+1 <= maxTokens {
		return toBoundary
	}
	// A zero/negative limit never admits; the boundary is the bounded advisory
	// value (and avoids a nextFrac > 1 below).
	if maxTokens <= 0 {
		return toBoundary
	}
	// cur is at/over the limit: even at the boundary the new prev still blocks,
	// so wait for it to decay into the next window. Solve cur*(1-frac) + 1 ==
	// maxTokens. cur > 0 here (cur+1 > maxTokens >= 1).
	nextFrac := 1 - (float64(maxTokens)-1)/float64(cur)
	return toBoundary + time.Duration(nextFrac*float64(size)) + 1
}
