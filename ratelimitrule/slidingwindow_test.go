package ratelimitrule

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const win = int64(time.Second)

// fixedClock pins the strategy to a settable instant.
type fixedClock struct{ ns int64 }

func (c *fixedClock) now() int64 { return c.ns }

func newTestSliding(rate int, startWindow int64) (*slidingWindowStrategy, *fixedClock) {
	clock := &fixedClock{ns: startWindow * win}
	s := newSlidingWindow(rate, time.Second)
	s.now = clock.now
	return s, clock
}

func TestSlidingWindow_TakeWithinWindow(t *testing.T) {
	t.Parallel()

	s, _ := newTestSliding(2, 100)
	assert.True(t, s.Take("k"))
	assert.True(t, s.Take("k"))
	assert.False(t, s.Take("k"), "third request in the window is rejected")
	assert.True(t, s.Take("other"), "keys have independent budgets")
}

func TestSlidingWindow_PrevWindowDecays(t *testing.T) {
	t.Parallel()

	s, clock := newTestSliding(2, 100)
	require.True(t, s.Take("k"))
	require.True(t, s.Take("k"))

	// At the boundary the previous window still counts in full.
	clock.ns = 101 * win
	assert.False(t, s.Take("k"), "weighted count 2 (+1) exceeds max at frac 0")

	// Halfway through the next window prev has decayed to 1: 1+1 <= 2 admits.
	clock.ns = 101*win + win/2
	assert.True(t, s.Take("k"))
	assert.False(t, s.Take("k"), "budget spent again")
}

func TestSlidingWindow_GapClearsBothGenerations(t *testing.T) {
	t.Parallel()

	s, clock := newTestSliding(1, 100)
	require.True(t, s.Take("k"))
	require.False(t, s.Take("k"))

	clock.ns = 105 * win // >= 2 windows idle
	assert.True(t, s.Take("k"), "an idle gap frees the whole budget")
}

func TestSlidingWindow_BackwardClockIsAbsorbed(t *testing.T) {
	t.Parallel()

	s, clock := newTestSliding(1, 100)
	require.True(t, s.Take("k"))

	clock.ns = 99 * win // clock stepped back a window
	assert.False(t, s.Take("k"), "no negative roll: cur still counts")
}

func TestSlidingWindow_ZeroMaxAdmitsNothing(t *testing.T) {
	t.Parallel()

	s, _ := newTestSliding(0, 100)
	assert.False(t, s.Take("k"))
	assert.LessOrEqual(t, s.After("k"), time.Second, "advisory wait stays bounded")
}

func TestSlidingWindow_AfterIsNeverTooOptimistic(t *testing.T) {
	t.Parallel()

	// Property: whenever Take is blocked, advancing the clock by After admits.
	for _, rate := range []int{1, 2, 5} {
		s, clock := newTestSliding(rate, 100)
		for i := 0; i < 3*rate; i++ {
			for s.Take("k") { //nolint:revive // drain the budget
			}
			after := s.After("k")
			require.Greater(t, after, time.Duration(0), "blocked => positive wait (no boundary between calls here)")
			clock.ns += int64(after)
			require.True(t, s.Take("k"), "rate=%d round=%d: admitted at now+After", rate, i)
			clock.ns += win / 7 // drift inside the window
		}
	}
}

func TestSlidingWindow_AfterDoesNotMutate(t *testing.T) {
	t.Parallel()

	s, clock := newTestSliding(1, 100)
	require.True(t, s.Take("k"))
	clock.ns = 101 * win // one boundary later; After's roll must be read-only
	_ = s.After("k")
	assert.Equal(t, int64(100), s.window, "After must not advance the generations")
}

func TestAfterAt(t *testing.T) {
	t.Parallel()

	t.Run("free budget returns 0", func(t *testing.T) {
		assert.Zero(t, afterAt(2, 0, 0, win, 100*win))
		assert.Zero(t, afterAt(2, 0, 1, win, 100*win))
	})

	t.Run("relief within the window as prev decays", func(t *testing.T) {
		// max 2, prev 2, cur 0 at frac 0: admit when 2*(1-f)+1 <= 2 => f >= 0.5.
		got := afterAt(2, 2, 0, win, 100*win)
		assert.Equal(t, time.Duration(win/2)+1, got)
	})

	t.Run("relief at the boundary when cur fits", func(t *testing.T) {
		// max 2, prev 2, cur 1 at frac 0.9: in-window relief impossible
		// (targetFrac == 1), so wait for the boundary.
		now := 100*win + 9*win/10
		got := afterAt(2, 2, 1, win, now)
		assert.Equal(t, time.Duration(101*win-now), got)
	})

	t.Run("full current window must decay past the boundary", func(t *testing.T) {
		// max 2, cur 2 at frac 0: boundary + decay of the new prev (f >= 0.5).
		got := afterAt(2, 0, 2, win, 100*win)
		assert.Equal(t, time.Duration(win)+time.Duration(win/2)+1, got)
	})
}

func TestSlidingWindow_GenerationRecycling(t *testing.T) {
	t.Parallel()

	// Crossing one boundary keeps last-window counts as prev; crossing another
	// retires them. Verifies the map swap/clear bookkeeping.
	s, clock := newTestSliding(10, 100)
	require.True(t, s.Take("a"))
	require.True(t, s.Take("b"))

	clock.ns = 101 * win
	require.True(t, s.Take("a"))
	s.mu.Lock()
	assert.Equal(t, 1, s.prev["a"])
	assert.Equal(t, 1, s.prev["b"])
	assert.Equal(t, 1, s.cur["a"])
	assert.Empty(t, s.cur["b"])
	s.mu.Unlock()

	clock.ns = 102 * win
	require.True(t, s.Take("c"))
	s.mu.Lock()
	assert.Empty(t, s.prev["b"], "b's last activity is two windows old and fully retired")
	assert.Equal(t, 1, s.prev["a"])
	s.mu.Unlock()
}

func TestSlidingWindow_AfterValueAcrossBoundary(t *testing.T) {
	t.Parallel()

	// After's read-only roll must DECAY the last window's count across a
	// boundary (d == 1: it becomes prev), not treat it as current — a
	// transposition there reports waits of up to ~2 windows instead of the
	// correct in-window decay. No Take between the fill and the assertions, so
	// the generations stay un-rolled and After's own switch is what's tested.
	s, clock := newTestSliding(2, 100)
	require.True(t, s.Take("k"))
	require.True(t, s.Take("k"))

	clock.ns = 101*win + win/4
	got := s.After("k")
	want := afterAt(2, 2, 0, win, clock.ns)
	assert.Equal(t, want, got, "one boundary later the old cur must be read as a decaying prev")
	require.Greater(t, got, time.Duration(0))
	assert.Less(t, got, time.Duration(win), "relief comes from in-window decay, not another boundary")

	clock.ns = 102 * win
	assert.Zero(t, s.After("k"), "two boundaries later both generations are stale: budget free")
}

func TestSlidingWindow_BackwardClockRecovery(t *testing.T) {
	t.Parallel()

	// After a backward step and recovery, the budget consumed before the step
	// must still count. Parapet's per-item roll regresses the window index on
	// the backward Take and forgets the counts on recovery (over-admission);
	// this implementation pins the high-water window — do not regress this.
	s, clock := newTestSliding(2, 100)
	clock.ns = 100*win + win/2
	require.True(t, s.Take("k"))
	require.True(t, s.Take("k"))

	clock.ns = 99*win + win/2 // clock steps back a window
	require.False(t, s.Take("k"), "blocked during the backward period")

	clock.ns = 100*win + 3*win/4 // clock recovers, same window as the fills
	assert.False(t, s.Take("k"), "the pre-step budget still counts after recovery")

	clock.ns = 101*win + 3*win/4 // next window: prev=2 decayed to 0.5 -> admit
	assert.True(t, s.Take("k"))
}
