package route

import (
	"fmt"
	"strings"
	"sync"
)

var globalRouteTable routeTable

type routeTable struct {
	mu               sync.RWMutex
	addrToTargetHost map[string]*RRLB
	addrToTargetPort map[string]string
	badAddr          badAddrTable
}

func init() {
	go globalRouteTable.badAddr.clearLoop()
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

	hostIP := nextIP(targetHost, &t.badAddr)
	if hostIP == "" {
		hostIP = addr
	}
	return fmt.Sprintf("%s:%s", hostIP, targetPort)
}

func (t *routeTable) SetHostRoute(routes map[string]*RRLB) {
	t.mu.Lock()
	t.addrToTargetHost = routes
	t.mu.Unlock()
}

func (t *routeTable) SetPortRoute(routes map[string]string) {
	t.mu.Lock()
	t.addrToTargetPort = routes
	t.mu.Unlock()
}

func Lookup(addr string) string {
	return globalRouteTable.Lookup(addr)
}

func SetHostRoute(routes map[string]*RRLB) {
	globalRouteTable.SetHostRoute(routes)
}

func SetPortRoute(routes map[string]string) {
	globalRouteTable.SetPortRoute(routes)
}

func MarkBad(addr string) {
	globalRouteTable.badAddr.MarkBad(addr)
}
