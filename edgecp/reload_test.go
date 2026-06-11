package edgecp

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/watch"
)

// watchAndRelist must relist via reload on EVERY watch (re)connect — including
// reconnects that deliver zero events. This is the fix for the silent-staleness
// bug: a change that lands in the gap between one watch closing and the next
// opening is never delivered (a bare Watch carries no resourceVersion), so
// without the reconnect relist it would persist until an unrelated later event
// or a process restart.
func TestWatchAndRelistRelistsOnEveryReconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var relists atomic.Int32
	established := make(chan *watch.FakeWatcher, 8)

	watchFn := func(context.Context) (watch.Interface, error) {
		w := watch.NewFake()
		established <- w
		return w, nil
	}
	reload := func(context.Context) error {
		relists.Add(1)
		return nil
	}
	// drain mirrors the real reloaders: return when the watch channel closes.
	drain := func(_ context.Context, ch <-chan watch.Event) {
		for range ch {
		}
	}

	go watchAndRelist(ctx, "test", watchFn, reload, drain)

	waitRelists := func(want int32) {
		t.Helper()
		require.Eventually(t, func() bool { return relists.Load() >= want },
			2*time.Second, 5*time.Millisecond, "want >= %d relists, got %d", want, relists.Load())
	}

	// First watch establishes → relist happens with NO events delivered.
	w1 := <-established
	waitRelists(1)

	// Close the watch with zero events in flight: drain returns, the loop
	// reconnects, and the reconnect MUST relist again (the gap-closing fix).
	w1.Stop()
	w2 := <-established
	waitRelists(2)

	// And once more, to show it's every reconnect, not just the first.
	w2.Stop()
	<-established
	waitRelists(3)
}

// A watchFn error must back off and retry without ever calling reload for that
// failed attempt, then relist once the watch finally establishes.
func TestWatchAndRelistRetriesWatchErrorThenRelists(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var relists atomic.Int32
	var attempts atomic.Int32
	established := make(chan *watch.FakeWatcher, 4)

	watchFn := func(context.Context) (watch.Interface, error) {
		if attempts.Add(1) == 1 {
			return nil, errors.New("api down")
		}
		w := watch.NewFake()
		established <- w
		return w, nil
	}
	reload := func(context.Context) error {
		relists.Add(1)
		return nil
	}
	drain := func(_ context.Context, ch <-chan watch.Event) {
		for range ch {
		}
	}

	go watchAndRelist(ctx, "test", watchFn, reload, drain)

	// The first attempt errored (no relist); the retry establishes and relists.
	w := <-established
	require.Eventually(t, func() bool { return relists.Load() == 1 },
		3*time.Second, 5*time.Millisecond, "relist must run only after the watch establishes")
	require.GreaterOrEqual(t, attempts.Load(), int32(2))
	w.Stop()
}
