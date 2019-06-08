package controller

import (
	"sync"
	"time"
)

type debounce struct {
	mu sync.Mutex
	t  *time.Timer
	f  func()
	d  time.Duration
}

func newDebounce(f func(), d time.Duration) *debounce {
	return &debounce{
		f: f,
		d: d,
	}
}

func (d *debounce) Call() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// first reload always block
	if d.t == nil {
		d.f()
		d.t = time.AfterFunc(0, func() {})
		return
	}

	d.t.Stop()
	d.t = time.AfterFunc(d.d, d.f)

}
