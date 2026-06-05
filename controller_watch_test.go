package controller

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type fakeWatcher struct{ ch chan watch.Event }

func (f *fakeWatcher) Stop()                          {}
func (f *fakeWatcher) ResultChan() <-chan watch.Event { return f.ch }

func TestWatchResource(t *testing.T) {
	ch := make(chan watch.Event, 8)
	w := &fakeWatcher{ch: ch}

	var store sync.Map
	var upserts, deletes atomic.Int32

	go watchResource[v1.Service](
		context.Background(), "", "services",
		func(context.Context, string) (watch.Interface, error) { return w, nil },
		func(context.Context, string) ([]v1.Service, error) { return nil, nil },
		&store,
		func(_ *v1.Service) { upserts.Add(1) },
		func(_ *v1.Service) { deletes.Add(1) },
		func() {},
	)

	svc := &v1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"}}

	// an object of the wrong concrete type is ignored: not stored, no callback
	ch <- watch.Event{Type: watch.Added, Object: &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pod"},
	}}

	// Added stores the object and fires onUpsert
	ch <- watch.Event{Type: watch.Added, Object: svc}
	assert.Eventually(t, func() bool {
		_, ok := store.Load("default/web")
		return ok && upserts.Load() == 1
	}, time.Second, time.Millisecond)

	// Deleted removes the object and fires onDelete
	ch <- watch.Event{Type: watch.Deleted, Object: svc}
	assert.Eventually(t, func() bool {
		_, ok := store.Load("default/web")
		return !ok && deletes.Load() == 1
	}, time.Second, time.Millisecond)

	// the ignored Pod event never produced a callback or store entry
	assert.Equal(t, int32(1), upserts.Load())
	assert.Equal(t, int32(1), deletes.Load())
}

// When a watch ends, watchResource relists and reconciles the store before
// reconnecting. This recovers from a Deleted event dropped in the watch gap: the
// stale store entry (which would otherwise route traffic to a vanished backend
// forever) is removed, and onResync fires to rebuild routing.
func TestWatchResourceResyncReconcilesStore(t *testing.T) {
	var store sync.Map
	// "default/stale" is in the store but NOT in the authoritative list — i.e. a
	// missed Deleted. "default/web" is the live object the list returns.
	store.Store("default/stale", &v1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "stale"}})

	listFn := func(context.Context, string) ([]v1.Service, error) {
		return []v1.Service{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"}},
		}, nil
	}

	// First watch hands back an already-closed channel so the event loop exits
	// immediately and triggers the resync; subsequent watches block forever so the
	// resync runs exactly once.
	var calls atomic.Int32
	watchFn := func(context.Context, string) (watch.Interface, error) {
		if calls.Add(1) == 1 {
			closed := make(chan watch.Event)
			close(closed)
			return &fakeWatcher{ch: closed}, nil
		}
		return &fakeWatcher{ch: make(chan watch.Event)}, nil
	}

	var resyncs atomic.Int32
	go watchResource[v1.Service](
		context.Background(), "", "services",
		watchFn, listFn, &store,
		func(*v1.Service) {}, func(*v1.Service) {},
		func() { resyncs.Add(1) },
	)

	assert.Eventually(t, func() bool {
		_, staleOK := store.Load("default/stale")
		_, webOK := store.Load("default/web")
		return !staleOK && webOK && resyncs.Load() >= 1
	}, 2*time.Second, time.Millisecond,
		"resync must drop the stale entry, keep the listed one, and fire onResync")
}
