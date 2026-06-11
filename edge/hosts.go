package edge

import (
	"sync"
	"sync/atomic"
)

// EdgeHosts holds the Ingress-declared known-host set fetched from the control
// plane's GET /v1/hosts. It is the request metric's host oracle: the metric
// bounds the parapet_requests `host` label to this set (unknown hosts collapse
// to "other"), giving EXACT per-host labels for an observation system while
// keeping series cardinality bounded under a random-Host flood.
//
// Always-on (the metric is always mounted) and standalone: a stale or empty set
// only over-collapses the label, never a WAF/limit signal, so it has no
// atomicity coupling with the WAF/ratelimit payloads. Lock-free reads via the
// atomic pointer.
type EdgeHosts struct {
	hosts atomic.Pointer[map[string]struct{}]

	// generation of the currently-loaded snapshot (0 until the first fetch applies).
	generation atomic.Uint64

	mu   sync.Mutex
	etag string
}

// NewEdgeHosts returns an empty host set — every host is unknown (collapses to
// "other") until the first fetch lands.
func NewEdgeHosts() *EdgeHosts {
	h := &EdgeHosts{}
	empty := map[string]struct{}{}
	h.hosts.Store(&empty)
	return h
}

// Etag returns the ETag of the currently-loaded set (sent as If-None-Match).
func (h *EdgeHosts) Etag() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.etag
}

// Generation returns the currently-loaded snapshot's generation (0 until the
// first fetch applies).
func (h *EdgeHosts) Generation() uint64 { return h.generation.Load() }

// Update swaps in a fetched host set wholesale. There is no compile step — the
// list is already-validated wire data — so it always applies and advances the
// etag/generation.
func (h *EdgeHosts) Update(generation uint64, hosts []string, etag string) {
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

// IsKnownHost reports whether host is one an Ingress declares. A host not in the
// set collapses to the metric's "other" bucket, bounding series cardinality.
func (h *EdgeHosts) IsKnownHost(host string) bool {
	m := h.hosts.Load()
	if m == nil {
		return false
	}
	_, ok := (*m)[host]
	return ok
}
