package route

import (
	"fmt"
	"strings"
	"sync"
)

type Table struct {
	mu               sync.RWMutex
	onceStartBgJob   sync.Once
	addrToTargetHost map[string]*RRLB
	addrToTargetPort map[string]string
	badAddr          badAddrTable
}

func (t *Table) runBackgroundJob() {
	go t.badAddr.clearLoop()
}

// Lookup returns target pod's addr to connect to.
// If target pod's addr is not found in table, it will return addr as is.
func (t *Table) Lookup(addr string) string {
	// addr only in dns name service.namespace.svc.cluster.local:port
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		// invalid format
		return addr
	}
	host := addr[:i]

	t.mu.RLock()
	hostTable := t.addrToTargetHost
	portTable := t.addrToTargetPort
	t.mu.RUnlock()

	targetHost, ok := hostTable[host]
	if !ok {
		// host not found in table, lets proxy try to resolve it from dialer
		return addr
	}

	targetPort, ok := portTable[addr]
	if !ok {
		// port not found in table, lets proxy connect to service directly
		return addr
	}

	// found host and port, proxy will connect to pod directly

	hostIP := nextIP(targetHost, &t.badAddr)
	if hostIP == "" {
		// not found any pod, lets proxy try to resolve it from dialer
		// this case should not happen, if SetHostRoute is called correctly
		return addr
	}
	return fmt.Sprintf("%s:%s", hostIP, targetPort)
}

// SetHostRoute sets route from host to RRLB (IPs)
//
// In Kubernetes cluster, host is dns name service.namespace.svc.cluster.local
// and IPs is list of pod IPs from service's endpoint.
func (t *Table) SetHostRoute(routes map[string]*RRLB) {
	t.onceStartBgJob.Do(t.runBackgroundJob)

	t.mu.Lock()
	t.addrToTargetHost = routes
	t.mu.Unlock()
}

// SetPortRoute sets route from service's addr to pod's port
// to make proxy connect directly to pod.
func (t *Table) SetPortRoute(routes map[string]string) {
	t.mu.Lock()
	t.addrToTargetPort = routes
	t.mu.Unlock()
}

func (t *Table) MarkBad(addr string) {
	t.badAddr.MarkBad(addr)
}
