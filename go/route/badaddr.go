package route

import (
	"log/slog"
	"net"
	"sync"
	"time"
)

type badAddrTable struct {
	addrs sync.Map
}

const badDuration = 2 * time.Second

func (t *badAddrTable) MarkBad(addr string) {
	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
	// Log only on the transition into a bad state. A sustained outage re-marks
	// the same host on every failed dial; logging each one would flood the log
	// exactly when it's busiest. A host that recovered (its entry expired) and
	// fails again logs once more, so distinct outage episodes are still visible.
	if t.mark(host) {
		slog.Warn("badAddrTable: mark bad", "host", host)
	}
}

// mark records host as bad and reports whether it transitioned from a not-bad
// state (absent or expired) — used to log once per outage episode.
func (t *badAddrTable) mark(host string) (transitioned bool) {
	transitioned = !t.IsBad(host)
	t.addrs.Store(host, time.Now())
	return
}

func (t *badAddrTable) IsBad(host string) bool {
	if t == nil {
		return false
	}
	p, ok := t.addrs.Load(host)
	if !ok {
		return false
	}
	return time.Since(p.(time.Time)) <= badDuration
}

func (t *badAddrTable) Clear() {
	start := time.Now()
	var total int
	t.addrs.Range(func(key, value any) bool {
		k, v := key.(string), value.(time.Time)
		if time.Since(v) > badDuration {
			t.addrs.Delete(k)
			total++
		}
		return true
	})
	if total > 0 {
		slog.Info("badAddrTable: cleared table", "total", total, "duration", time.Since(start))
	}
}

func (t *badAddrTable) clearLoop() {
	slog.Info("badAddrTable: clear loop started")

	const clearDuration = 10 * time.Minute

	for {
		time.Sleep(clearDuration)
		t.Clear()
	}
}
