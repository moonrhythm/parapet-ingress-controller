package ratelimitrule

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFixedWindow_AfterUsesEpochGrid(t *testing.T) {
	t.Parallel()

	// Parapet's FixedWindowStrategy.Take buckets on the Unix-epoch grid but its
	// After computes the reset on time.Truncate's zero-time grid; for a 7s
	// window the grids are offset by 62135596800 mod 7 = 4s, so the raw wait
	// can be 4s too short. The wrapper must report the wait to the next
	// EPOCH-grid boundary — when the blocked budget actually resets.
	const size = int64(7 * time.Second)
	for attempt := 0; attempt < 5; attempt++ {
		s := newFixedWindow(1, 7*time.Second)
		require.True(t, s.Take("k"))
		if s.Take("k") {
			continue // a window boundary fell between the takes; retry
		}
		// Pin the boundary computation to a known instant inside the same window.
		now := time.Now().UnixNano()
		s.now = func() int64 { return now }
		got := s.After("k")
		if got == 0 {
			continue // boundary passed between the blocked Take and After; retry
		}
		want := time.Duration((now/size+1)*size - now)
		assert.Equal(t, want, got, "blocked wait must land exactly on the epoch-grid reset")
		return
	}
	t.Fatal("could not observe a blocked take within one 7s window after 5 attempts")
}

func TestFixedWindow_AfterZeroWhenFree(t *testing.T) {
	t.Parallel()

	s := newFixedWindow(2, time.Hour)
	assert.Zero(t, s.After("k"), "untouched budget reports no wait")
	require.True(t, s.Take("k"))
	assert.Zero(t, s.After("k"), "remaining budget reports no wait")
}
