package controller

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/glog"
)

type rrlb struct {
	IPs     []string // immutable
	current uint32
}

func (lb *rrlb) Get() (ip string) {
	l := len(lb.IPs)
	if l == 0 {
		return ""
	}
	if l == 1 {
		return lb.IPs[0]
	}

	p := int(atomic.AddUint32(&lb.current, 1)) % l
	for k := 0; k < l; k++ { // try gets not bad address
		i := (p + k) % l
		ip = lb.IPs[i]
		if !globalBadAddrTable.IsBad(ip) {
			return
		}
	}
	return lb.IPs[p] // all bad, return first
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

	hostIP := targetHost.Get()
	if hostIP == "" {
		hostIP = addr
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

var globalBadAddrTable badAddrTable

func init() {
	go globalBadAddrTable.clearLoop()
}

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

	const clearDuration = 1 * time.Minute

	for {
		time.Sleep(clearDuration)
		t.Clear()
	}
}
