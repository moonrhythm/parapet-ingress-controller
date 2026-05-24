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
		&store,
		func(_ *v1.Service) { upserts.Add(1) },
		func() { deletes.Add(1) },
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
