package edgecp

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// TopologyStore holds the Ingress-derived edge topology distributed ONCE via
// GET /v1/topology: the WAF zone bindings, the rate-limit zone bindings (both as
// the path-aware routeZone map plus a legacy host→zoneKey map), and the
// known-host list. It supersedes the per-feature bindings/hosts that /v1/waf and
// /v1/ratelimit used to embed — the edge fetches the binding topology and the
// host set from one place and feeds it to its WAF matcher, rate-limit matcher,
// and the request metric's host-cardinality bound.
//
// The WAF and rate-limit RULE/limit sets still come from /v1/waf and
// /v1/ratelimit (and those stores still hold their own copy of the bindings to
// scope which zone rulesets a token receives — tenant isolation); this store is
// the single wire home for the bindings + hosts, fed by the same IngressReloader
// snapshot so the three never diverge mid-update.
//
// Lock-free reads via atomic pointers; mu held by the writer and by scoped() for
// a consistent snapshot, matching WafStore/RateLimitStore.
type TopologyStore struct {
	mu           sync.RWMutex
	wafHostZone  atomic.Pointer[map[string]string] // lowercased host -> waf zoneKey (legacy)
	wafRouteZone atomic.Pointer[map[string]string] // route pattern -> waf zoneKey
	rlHostZone   atomic.Pointer[map[string]string] // lowercased host -> ratelimit zoneKey (legacy)
	rlRouteZone  atomic.Pointer[map[string]string] // route pattern -> ratelimit zoneKey
	hosts        atomic.Pointer[[]string]          // sorted known hosts (IsKnownHost)
	gen          atomic.Uint64
	curEtag      atomic.Pointer[string]
}

func NewTopologyStore() *TopologyStore {
	s := &TopologyStore{}
	wh := map[string]string{}
	wr := map[string]string{}
	rh := map[string]string{}
	rr := map[string]string{}
	var hosts []string
	s.wafHostZone.Store(&wh)
	s.wafRouteZone.Store(&wr)
	s.rlHostZone.Store(&rh)
	s.rlRouteZone.Store(&rr)
	s.hosts.Store(&hosts)
	et := etagOfString("")
	s.curEtag.Store(&et)
	return s
}

// SetIngressDerived replaces every Ingress-derived input in one recompute, so a
// single Ingress reload can't be observed half-applied.
func (s *TopologyStore) SetIngressDerived(wafHostZone, wafRouteZone, rlHostZone, rlRouteZone map[string]string, hosts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wafHostZone.Store(&wafHostZone)
	s.wafRouteZone.Store(&wafRouteZone)
	s.rlHostZone.Store(&rlHostZone)
	s.rlRouteZone.Store(&rlRouteZone)
	s.hosts.Store(&hosts)
	s.recompute()
}

func (s *TopologyStore) recompute() {
	et := etagOfString(s.fingerprint())
	if prev := s.curEtag.Load(); prev != nil && *prev == et {
		return
	}
	s.gen.Add(1)
	s.curEtag.Store(&et)
}

func (s *TopologyStore) fingerprint() string {
	var b strings.Builder
	writeSortedMap(&b, *s.wafHostZone.Load())
	b.WriteByte(0)
	writeSortedMap(&b, *s.wafRouteZone.Load())
	b.WriteByte(0)
	writeSortedMap(&b, *s.rlHostZone.Load())
	b.WriteByte(0)
	writeSortedMap(&b, *s.rlRouteZone.Load())
	b.WriteByte(0)
	for _, h := range *s.hosts.Load() {
		b.WriteString(h)
		b.WriteByte(1)
	}
	return b.String()
}

// Version is the store's full-content etag — the opaque change signal for the
// /v1/events stream (per-edge scoping happens at fetch time).
func (s *TopologyStore) Version() string { return *s.curEtag.Load() }

// topologySnapshot is the per-edge topology payload: only the bindings and hosts
// the edge may serve (per allow).
type topologySnapshot struct {
	generation   uint64
	wafHostZone  map[string]string
	wafRouteZone map[string]string
	rlHostZone   map[string]string
	rlRouteZone  map[string]string
	hosts        []string
}

// scoped builds the per-edge topology, including only host bindings whose host
// the edge may serve, route bindings whose pattern-host the edge may serve, and
// the allowed hosts. Read under the lock so all five form one consistent
// snapshot (mirrors WafStore.scoped).
func (s *TopologyStore) scoped(allow func(host string) bool) topologySnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filterHostMap := func(m map[string]string) map[string]string {
		out := map[string]string{}
		for host, key := range m {
			if allow(host) {
				out[host] = key
			}
		}
		return out
	}
	filterRouteMap := func(m map[string]string) map[string]string {
		out := map[string]string{}
		for pattern, key := range m {
			if allow(patternHost(pattern)) {
				out[pattern] = key
			}
		}
		return out
	}

	allHosts := *s.hosts.Load()
	hosts := make([]string, 0, len(allHosts))
	for _, h := range allHosts {
		if allow(h) {
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)

	return topologySnapshot{
		generation:   s.gen.Load(),
		wafHostZone:  filterHostMap(*s.wafHostZone.Load()),
		wafRouteZone: filterRouteMap(*s.wafRouteZone.Load()),
		rlHostZone:   filterHostMap(*s.rlHostZone.Load()),
		rlRouteZone:  filterRouteMap(*s.rlRouteZone.Load()),
		hosts:        hosts,
	}
}
