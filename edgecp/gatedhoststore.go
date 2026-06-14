package edgecp

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// GatedHostsStore holds the per-token forward-auth-gated host set: every Ingress
// host whose Ingress carries the `parapet.moonrhythm.io/forward-auth` annotation
// (non-empty value), distributed via GET /v1/gated-hosts. The edge-proxy bypasses
// its response cache for these hosts — the cache key ignores Cookie, so a cached
// 200 for a forward-auth-gated host would leak pre-auth content to anonymous
// users.
//
// Unlike the known-host oracle, this set fails toward CACHING: a stale or empty
// set means the edge briefly does NOT bypass the cache for a newly-gated host, so
// timeliness matters — it is paired with the /v1/events poke so the fleet
// converges in ~seconds, not one poll interval. The in-cluster forward-auth gate
// stays authoritative regardless: a brief propagation window can never let the
// edge bypass auth, only briefly serve a cached copy of an already-public-looking
// response. Same scoping/ETag model as the other stores: lock-free reads via the
// atomic pointer, mu held by the writer and by scoped() for a consistent
// snapshot.
type GatedHostsStore struct {
	mu      sync.RWMutex
	hosts   atomic.Pointer[[]string] // sorted, deduped gated hosts
	gen     atomic.Uint64
	curEtag atomic.Pointer[string]
}

func NewGatedHostsStore() *GatedHostsStore {
	s := &GatedHostsStore{}
	var h []string
	s.hosts.Store(&h)
	et := etagOfString("")
	s.curEtag.Store(&et)
	return s
}

// SetHosts replaces the full gated-host list (sorted, deduped — see
// collectGatedHosts).
func (s *GatedHostsStore) SetHosts(hosts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts.Store(&hosts)
	s.recompute()
}

// recompute bumps the generation + etag when the content changes. Caller holds mu.
func (s *GatedHostsStore) recompute() {
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
func (s *GatedHostsStore) Version() string { return *s.curEtag.Load() }

// scoped returns the generation and only the gated hosts the edge may serve (per
// allow), read under the lock so the pair is a consistent snapshot.
func (s *GatedHostsStore) scoped(allow func(host string) bool) (generation uint64, hosts []string) {
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
