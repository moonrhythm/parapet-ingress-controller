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
	mu    sync.RWMutex
	addrs map[string]struct{}
}

func (t *badAddrTable) MarkBad(addr string) {
	glog.Warningf("badAddrTable: mark bad %s", addr)

	t.mu.Lock()
	if t.addrs == nil {
		t.addrs = make(map[string]struct{})
	}
	t.addrs[addr] = struct{}{}
	t.mu.Unlock()
}

func (t *badAddrTable) IsBad(addr string) bool {
	t.mu.RLock()
	_, ok := t.addrs[addr]
	t.mu.RUnlock()
	return ok
}

func (t *badAddrTable) Clear() {
	t.mu.Lock()
	t.addrs = nil
	t.mu.Unlock()
}

func (t *badAddrTable) clearLoop() {
	glog.Info("badAddrTable: clear loop started")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.Clear()
		}
	}
}
