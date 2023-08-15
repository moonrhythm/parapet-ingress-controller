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
	slog.Warn("badAddrTable: mark bad", "host", host)
	t.addrs.Store(host, time.Now())
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
