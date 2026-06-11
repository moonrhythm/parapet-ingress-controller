package edgecp

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// HostsStore holds the per-token known-host list (every Ingress-declared host),
// distributed via GET /v1/hosts. It is the edge request metric's host oracle:
// the edge bounds the parapet_requests `host` label to this set so a random-Host
// flood can't grow series cardinality, with EXACT per-host labels — unlike a
// cert-derived bound, which would bucket every subdomain of a wildcard cert
// under one series.
//
// It is deliberately STANDALONE — not bundled into /v1/waf or /v1/ratelimit —
// for two reasons: the metric is always on (even with WAF + rate-limiting off),
// and a stale host list only over-collapses the metric label to "other" (a
// cardinality bound, never a WAF/limit correctness signal), so it has no
// atomicity coupling with those payloads. Same scoping/ETag model as the other
// stores: lock-free reads via the atomic pointer, mu held by the writer and by
// scoped() for a consistent snapshot.
type HostsStore struct {
	mu      sync.RWMutex
	hosts   atomic.Pointer[[]string] // sorted, deduped known hosts
	gen     atomic.Uint64
	curEtag atomic.Pointer[string]
}

func NewHostsStore() *HostsStore {
	s := &HostsStore{}
	var h []string
	s.hosts.Store(&h)
	et := etagOfString("")
	s.curEtag.Store(&et)
	return s
}

// SetHosts replaces the full known-host list (sorted, deduped — see
// collectIngressHosts).
func (s *HostsStore) SetHosts(hosts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts.Store(&hosts)
	s.recompute()
}

// recompute bumps the generation + etag when the content changes. Caller holds mu.
func (s *HostsStore) recompute() {
	var b strings.Builder
	for _, h := range *s.hosts.Load() {
		b.WriteString(h)
		b.WriteByte(0)
	}
	et := etagOfString(b.String())
	if prev := s.curEtag.Load(); prev != nil && *prev == et {
		return
	}
	s.gen.Add(1)
	s.curEtag.Store(&et)
}

// Version is the store's full-content etag — the opaque change signal for the
// /v1/events stream (per-edge scoping happens at fetch time).
func (s *HostsStore) Version() string { return *s.curEtag.Load() }

// scoped returns the generation and only the hosts the edge may serve (per allow),
// read under the lock so the pair is a consistent snapshot.
func (s *HostsStore) scoped(allow func(host string) bool) (generation uint64, hosts []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := *s.hosts.Load()
	out := make([]string, 0, len(all))
	for _, h := range all {
		if allow(h) {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return s.gen.Load(), out
}
