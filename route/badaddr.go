package route

import (
	"net"
	"sync"
	"time"

	"github.com/golang/glog"
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
	glog.Warningf("badAddrTable: mark bad %s", host)
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
	var clear int
	t.addrs.Range(func(key, value any) bool {
		k, v := key.(string), value.(time.Time)
		if time.Since(v) > badDuration {
			t.addrs.Delete(k)
			clear++
		}
		return true
	})
	if clear > 0 {
		glog.Infof("badAddrTable: cleared table in %s, removed %d records", time.Since(start), clear)
	}
}

func (t *badAddrTable) clearLoop() {
	glog.Info("badAddrTable: clear loop started")

	const clearDuration = 10 * time.Minute

	for {
		time.Sleep(clearDuration)
		t.Clear()
	}
}
