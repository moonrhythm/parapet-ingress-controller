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

func (t *Table) RunBackgroundJob() {
	t.onceStartBgJob.Do(func() {
		go t.badAddr.clearLoop()
	})
}

func (t *Table) Lookup(addr string) string {
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

func (t *Table) SetHostRoute(routes map[string]*RRLB) {
	t.mu.Lock()
	t.addrToTargetHost = routes
	t.mu.Unlock()
}

func (t *Table) SetPortRoute(routes map[string]string) {
	t.mu.Lock()
	t.addrToTargetPort = routes
	t.mu.Unlock()
}

func (t *Table) MarkBad(addr string) {
	t.badAddr.MarkBad(addr)
}
