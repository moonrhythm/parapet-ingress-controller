package route

import (
	"net"
	"strings"
	"sync"
)

type Table struct {
	mu                 sync.RWMutex
	onceStartBgJob     sync.Once
	addrToTargetHost   map[string]*RRLB
	addrToTargetPort   map[string]string
	addrToExternalName map[string]string
	badAddr            badAddrTable
}

func (t *Table) runBackgroundJob() {
	go t.badAddr.clearLoop()
}

// Lookup returns the target pod's addr to connect to.
// If the target pod's addr is not found in the table, it will return an empty string
func (t *Table) Lookup(addr string) string {
	// addr only in dns name service.namespace.svc.cluster.local:port
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		// invalid format
		return ""
	}
	host := addr[:i]

	t.mu.RLock()
	targetHost, okHost := t.addrToTargetHost[host]
	externalName, okExt := t.addrToExternalName[host]
	targetPort, okPort := t.addrToTargetPort[addr]
	t.mu.RUnlock()

	if !okPort {
		// port not found in table
		return ""
	}

	if okHost {
		// pod-backed service: round-robin a healthy pod IP.
		hostIP := targetHost.Get(&t.badAddr)
		if hostIP == "" {
			// not found any pod
			return ""
		}
		// JoinHostPort brackets IPv6 literals (EndpointSlices surface IPv6 pod IPs
		// on dual-stack services); for IPv4/hostnames it is a plain host:port join.
		return net.JoinHostPort(hostIP, targetPort)
	}

	if okExt {
		// ExternalName service: dial the external DNS name directly — the dialer's
		// net.Resolver resolves it at connect time. No RRLB/badAddr: there is a
		// single target, and transient failures are handled by the retry path.
		return net.JoinHostPort(externalName, targetPort)
	}

	// neither a pod route nor an externalName route for this host
	return ""
}

// SetHostRoutes sets route from host to RRLB (IPs)
//
// In Kubernetes cluster, host is dns name service.namespace.svc.cluster.local
// and IPs is list of pod IPs from service's endpoint.
func (t *Table) SetHostRoutes(routes map[string]*RRLB) {
	t.onceStartBgJob.Do(t.runBackgroundJob)

	t.mu.Lock()
	t.addrToTargetHost = routes
	t.mu.Unlock()
}

func (t *Table) SetHostRoute(host string, lb *RRLB) {
	t.onceStartBgJob.Do(t.runBackgroundJob)

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.addrToTargetHost == nil {
		t.addrToTargetHost = map[string]*RRLB{}
	}
	if lb != nil {
		t.addrToTargetHost[host] = lb
	} else {
		delete(t.addrToTargetHost, host)
	}
}

// SetPortRoutes sets route from service's addr to pod's port
// to make proxy connect directly to pod.
func (t *Table) SetPortRoutes(routes map[string]string) {
	t.mu.Lock()
	t.addrToTargetPort = routes
	t.mu.Unlock()
}

// SetExternalNameRoutes sets route from a service's host
// (service.namespace.svc.cluster.local) to its spec.externalName — an external
// DNS name dialed directly instead of a pod IP. It is a full replace, mirroring
// SetPortRoutes, and is owned solely by the service reload, so it never races the
// incremental endpoint host-route path (SetHostRoute). A host present here but not
// in addrToTargetHost (an ExternalName service has no Endpoints) resolves via the
// externalName branch in Lookup.
func (t *Table) SetExternalNameRoutes(routes map[string]string) {
	t.mu.Lock()
	t.addrToExternalName = routes
	t.mu.Unlock()
}

func (t *Table) MarkBad(addr string) {
	t.badAddr.MarkBad(addr)
}
