package controller

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

type rrlb struct {
	IPs     []string
	current uint32
}

func (lb *rrlb) Get() string {
	l := len(lb.IPs)
	if l == 0 {
		return ""
	}
	if l == 1 {
		return lb.IPs[0]
	}

	p := atomic.AddUint32(&lb.current, 1)
	i := int(p) % l
	return lb.IPs[i]
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

	hostIP := targetHost.Get()
	if hostIP == "" {
		return addr
	}

	targetPort, ok := portTable[addr]
	if !ok {
		return addr
	}

	return fmt.Sprintf("%s:%s", hostIP, targetPort)
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
