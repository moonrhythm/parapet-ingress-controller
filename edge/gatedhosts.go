package edge

import (
	"sync"
	"sync/atomic"
)

// EdgeGatedHosts holds the forward-auth-gated host set fetched from the control
// plane's GET /v1/gated-hosts — every Ingress host whose Ingress carries the
// `parapet.moonrhythm.io/forward-auth` annotation. The edge-proxy bypasses its
// response cache (never serve-from, never store) for these hosts: the cache key
// ignores Cookie, so a cached 200 for a forward-auth-gated host would leak
// pre-auth content to anonymous users. The in-cluster forward-auth gate stays
// authoritative regardless; this only closes the edge-cache bypass of it.
//
// Lock-free reads via the atomic pointer. A stale or empty set fails toward
// caching (the edge briefly does NOT bypass for a newly-gated host), so the
// /v1/events poke keeps it timely.
type EdgeGatedHosts struct {
	hosts atomic.Pointer[map[string]struct{}]

	// generation of the currently-loaded snapshot (0 until the first fetch applies).
	generation atomic.Uint64

	mu   sync.Mutex
	etag string
}

// NewEdgeGatedHosts returns an empty gated-host set — no host bypasses the cache
// until the first fetch lands.
func NewEdgeGatedHosts() *EdgeGatedHosts {
	h := &EdgeGatedHosts{}
	empty := map[string]struct{}{}
	h.hosts.Store(&empty)
	return h
}

// Etag returns the ETag of the currently-loaded set (sent as If-None-Match).
func (h *EdgeGatedHosts) Etag() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.etag
}

// Generation returns the currently-loaded snapshot's generation (0 until the
// first fetch applies).
func (h *EdgeGatedHosts) Generation() uint64 { return h.generation.Load() }

// Update swaps in a fetched gated-host set wholesale. There is no compile step —
// the list is already-validated wire data — so it always applies and advances the
// etag/generation.
func (h *EdgeGatedHosts) Update(generation uint64, hosts []string, etag string) {
	hs := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		hs[host] = struct{}{}
	}
	h.hosts.Store(&hs)

	h.mu.Lock()
	h.etag = etag
	h.mu.Unlock()
	h.generation.Store(generation)
}

// IsGatedHost reports whether host is forward-auth-gated. The edge-proxy bypasses
// its response cache for a host this returns true for.
func (h *EdgeGatedHosts) IsGatedHost(host string) bool {
	m := h.hosts.Load()
	if m == nil {
		return false
	}
	_, ok := (*m)[host]
	return ok
}
