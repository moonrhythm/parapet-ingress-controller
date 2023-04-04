package controller

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/glog"
)

type rrlb struct {
	IPs     []string
	current uint32
}

func (lb *rrlb) Get() (ip string, length int) {
	l := len(lb.IPs)
	if l == 0 {
		return "", l
	}
	if l == 1 {
		return lb.IPs[0], l
	}

	p := atomic.AddUint32(&lb.current, 1)
	i := int(p) % l
	return lb.IPs[i], l
}

var globalRouteTable routeTable

type routeTable struct {
	mu               sync.RWMutex
	addrToTargetHost map[string]*rrlb
	addrToTargetPort map[string]string
}

func (t *routeTable) Lookup(addr string) string {
	// addr only in dns name service.namespace.svc.cluster.local:port
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr
	}
	host := addr[:i]

	t.mu.RLock()
	hostTable := t.addrToTargetHost
	portTable := t.addrToTargetPort
	t.mu.RUnlock()

	targetHost, ok := hostTable[host]
	if !ok {
		return addr
	}

	targetPort, ok := portTable[addr]
	if !ok {
		return addr
	}

	for i := 0; i < 100; i++ { // hard limit to prevent infinite loop
		hostIP, n := targetHost.Get()
		if hostIP == "" {
			return addr
		}

		addr = fmt.Sprintf("%s:%s", hostIP, targetPort)
		if n <= 1 || i >= n+2 || !globalBadAddrTable.IsBad(addr) {
			return addr
		}
	}
	return addr
}

func (t *routeTable) SetHostRoute(routes map[string]*rrlb) {
	t.mu.Lock()
	t.addrToTargetHost = routes
	t.mu.Unlock()
}

func (t *routeTable) SetPortRoute(routes map[string]string) {
	t.mu.Lock()
	t.addrToTargetPort = routes
	t.mu.Unlock()
}

var globalBadAddrTable badAddrTable

func init() {
	go globalBadAddrTable.clearLoop()
}

type badAddrTable struct {
	addrs sync.Map
}

const badDuration = 2 * time.Second

func (t *badAddrTable) MarkBad(addr string) {
	glog.Warningf("badAddrTable: mark bad %s", addr)
	t.addrs.Store(addr, time.Now())
}

func (t *badAddrTable) IsBad(addr string) bool {
	p, ok := t.addrs.Load(addr)
	if !ok {
		return false
	}
	return time.Since(p.(time.Time)) <= badDuration
}

func (t *badAddrTable) Clear() {
	glog.Info("badAddrTable: clearing table")

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
	glog.Infof("badAddrTable: cleared table in %s, removed %d records", time.Since(start), clear)
}

func (t *badAddrTable) clearLoop() {
	glog.Info("badAddrTable: clear loop started")

	const clearDuration = 1 * time.Minute

	for {
		time.Sleep(clearDuration)
		t.Clear()
	}
}
