package ratelimitrule

import (
	"time"

	"github.com/moonrhythm/parapet/pkg/ratelimit"
)

// fixedWindowStrategy is parapet's FixedWindowStrategy with a corrected After.
// Parapet's Take buckets on the Unix-epoch grid (UnixNano()/Size) but its After
// computes the reset via time.Time.Truncate, which rounds on the ZERO-time
// (year 1) grid — the two coincide only for windows that divide the year-1→
// epoch offset (62135596800s; 1s/1m/1h all do, which is why the annotation
// limiters never hit this). For any other window (7s, 90s, ...) parapet's
// After can be up to (offset mod window) too SHORT, so a compliant client
// honoring Retry-After retries into another denial. This wrapper keeps
// parapet's blocked/free decision and recomputes the wait on the same epoch
// grid Take uses, preserving the never-too-optimistic property the sliding
// implementation guarantees.
type fixedWindowStrategy struct {
	inner ratelimit.FixedWindowStrategy
	size  int64        // window size in ns, > 0 (validated by SetLimits)
	now   func() int64 // test hook returning ns since epoch; nil = wall clock
}

func newFixedWindow(rate int, window time.Duration) *fixedWindowStrategy {
	return &fixedWindowStrategy{
		inner: ratelimit.FixedWindowStrategy{Max: rate, Size: window},
		size:  int64(window),
	}
}

func (s *fixedWindowStrategy) Take(key string) bool { return s.inner.Take(key) }
func (s *fixedWindowStrategy) Put(key string)       { s.inner.Put(key) }

// After delegates the blocked/free decision to parapet (whose window-outdated
// and budget checks are on the correct epoch grid) and, when blocked, returns
// the wait to the next epoch-grid boundary — exactly when a blocked fixed
// window's budget resets.
func (s *fixedWindowStrategy) After(key string) time.Duration {
	if s.inner.After(key) <= 0 {
		return 0
	}
	now := time.Now().UnixNano()
	if s.now != nil {
		now = s.now()
	}
	return time.Duration((now/s.size+1)*s.size - now)
}
