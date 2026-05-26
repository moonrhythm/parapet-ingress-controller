package debounce

import (
	"sync"
	"time"
)

type Debounce struct {
	mu sync.Mutex
	t  *time.Timer
	f  func()
	d  time.Duration
}

func New(f func(), d time.Duration) *Debounce {
	return &Debounce{
		f: f,
		d: d,
	}
}

func (d *Debounce) Call() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// first reload always block
	if d.t == nil {
		d.f()
		d.t = time.AfterFunc(0, func() {})
		return
	}

	if d.t != nil {
		d.t.Stop()
	}
	d.t = time.AfterFunc(d.d, d.f)
}
