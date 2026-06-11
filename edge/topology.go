package edge

import (
	"net/http"
	"sync"
	"sync/atomic"
)

// EdgeTopology holds the Ingress-derived topology fetched from the control
// plane's GET /v1/topology: the WAF zone matcher, the rate-limit zone matcher,
// and the known-host set. It is the single source the edge WAF, the edge rate
// limiter, and the request metric read — replacing the per-feature bindings the
// /v1/waf and /v1/ratelimit payloads used to embed.
//
// Zone resolution is PATH-AWARE: the CP ships the controller's own route
// patterns and the matcher runs them through a real http.ServeMux, so the edge
// resolves a request's zone exactly as the core does. The known-host set bounds
// the request metric's host label and the rate limiter's host-key collapse to
// the controller's IsKnownHost set.
type EdgeTopology struct {
	wafMatcher atomic.Pointer[zoneMatcher]         // host+path -> waf zoneKey
	rlMatcher  atomic.Pointer[zoneMatcher]         // host+path -> ratelimit zoneKey
	knownHosts atomic.Pointer[map[string]struct{}] // Ingress-declared hosts

	// generation of the currently-loaded snapshot (0 until the first fetch applies).
	generation atomic.Uint64

	mu   sync.Mutex
	etag string
}

// NewEdgeTopology returns an empty topology (no bindings, no known hosts) — every
// request resolves to no zone and every host is unknown until the first fetch.
func NewEdgeTopology() *EdgeTopology {
	t := &EdgeTopology{}
	t.wafMatcher.Store(newZoneMatcher(nil, nil))
	t.rlMatcher.Store(newZoneMatcher(nil, nil))
	empty := map[string]struct{}{}
	t.knownHosts.Store(&empty)
	return t
}

// Etag returns the ETag of the currently-loaded topology (sent as If-None-Match).
func (t *EdgeTopology) Etag() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.etag
}

// Generation returns the currently-loaded snapshot's generation (0 until the
// first fetch applies).
func (t *EdgeTopology) Generation() uint64 { return t.generation.Load() }

// Update installs a fetched topology snapshot. The two matchers and the
// known-host set are swapped wholesale (each an independent atomic swap; a
// request racing the swap reads a consistent prior-or-next snapshot of each).
// Unlike the WAF/rate-limit Updates there is no compile step — the maps are
// already-validated wire data — so it always applies and advances the
// etag/generation.
func (t *EdgeTopology) Update(generation uint64, wafRouteZone, wafHostZone, rlRouteZone, rlHostZone map[string]string, hosts []string, etag string) {
	t.wafMatcher.Store(newZoneMatcher(wafRouteZone, wafHostZone))
	t.rlMatcher.Store(newZoneMatcher(rlRouteZone, rlHostZone))
	hs := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		hs[h] = struct{}{}
	}
	t.knownHosts.Store(&hs)

	t.mu.Lock()
	t.etag = etag
	t.mu.Unlock()
	t.generation.Store(generation)
}

// resolveWAFZone returns the WAF zone key bound to the request's host+path.
func (t *EdgeTopology) resolveWAFZone(r *http.Request) (string, bool) {
	if m := t.wafMatcher.Load(); m != nil {
		return m.resolve(r)
	}
	return "", false
}

// resolveRLZone returns the rate-limit zone key bound to the request's host+path.
func (t *EdgeTopology) resolveRLZone(r *http.Request) (string, bool) {
	if m := t.rlMatcher.Load(); m != nil {
		return m.resolve(r)
	}
	return "", false
}

// IsKnownHost reports whether host is one an Ingress declares. A host not in the
// set collapses (the request metric's "other" bucket, the rate limiter's shared
// host-key bucket), mirroring the controller's IsKnownHost cardinality bound.
func (t *EdgeTopology) IsKnownHost(host string) bool {
	m := t.knownHosts.Load()
	if m == nil {
		return false
	}
	_, ok := (*m)[host]
	return ok
}
