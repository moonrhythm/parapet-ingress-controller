package edge

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/moonrhythm/parapet"

	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
	"github.com/moonrhythm/parapet-ingress-controller/ratelimitrule"
)

// EdgeRateLimit holds the compiled global limit set plus tenant zones fetched
// from the control plane, and exposes them as parapet middleware. It reuses
// ratelimitrule (the same runtime the controller uses: hot-swappable Limiter,
// fixed/sliding strategies, all-or-nothing SetLimits with per-limit counter
// carry-over), so a limit shapes traffic identically at the edge and at
// parapet — but counters are PER EDGE, exactly as the controller's are per
// pod. The edge enforcing a limit does not relieve the core's own enforcement;
// each layer counts what it sees.
//
// Eval order mirrors the controller: global first, then the zone bound to the
// request route. Zone resolution is PATH-AWARE (same zoneMatcher as the edge
// WAF: the controller's own route patterns on a real http.ServeMux), so two
// ingresses sharing a host with different paths and different zones resolve
// exactly as they do at the core. Mounted AFTER the edge WAF so WAF-blocked
// traffic never burns rate budget, and BEFORE the response cache so
// edge-enforced limits apply to cache hits too.
type EdgeRateLimit struct {
	global *ratelimitrule.Limiter
	zones  atomic.Pointer[map[string]*ratelimitrule.Limiter] // zoneKey -> compiled zone
	topo   *EdgeTopology                                     // shared: host+path -> zoneKey + known-host set (from /v1/topology)

	newZone func(key string) *ratelimitrule.Limiter

	generation atomic.Uint64

	mu   sync.Mutex
	etag string
}

// NewEdgeRateLimit builds an empty edge rate limiter. country/asn are the GeoIP
// resolvers (the same ones the edge WAF uses); nil makes SetLimits reject
// country/asn-keyed limits — all-or-nothing, so a geo-keyed limit set requires
// the GeoIP databases at the edge (same parity note as the WAF, see EDGE.md).
func NewEdgeRateLimit(country func(*http.Request) string, asn func(*http.Request) int64, topo *EdgeTopology) *EdgeRateLimit {
	e := &EdgeRateLimit{topo: topo}
	newLimiter := func(namePrefix string) *ratelimitrule.Limiter {
		return &ratelimitrule.Limiter{
			NamePrefix: namePrefix,
			// observe (not metric) keeps the controller's init-materialized
			// core-trust series off the edge's /metrics — same boundary as the
			// edge WAF's eval observer.
			Observe: observe.RateLimit,
			// Host-key collapse reads the live Ingress-declared host set (shared
			// EdgeTopology), so a host added by a later topology fetch is honored
			// without recompiling limits, mirroring the controller's IsKnownHost.
			KnownHost: topo.IsKnownHost,
			Country:   country,
			ASN:       asn,
		}
	}
	e.global = newLimiter("global")
	e.newZone = func(key string) *ratelimitrule.Limiter { return newLimiter("zone:" + key) }
	empty := map[string]*ratelimitrule.Limiter{}
	e.zones.Store(&empty)
	return e
}

// Etag returns the ETag of the currently-loaded config (sent as If-None-Match).
func (e *EdgeRateLimit) Etag() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.etag
}

// Update compiles and installs a fetched payload: the global limit set and the
// zone limit sets. The zone BINDINGS and the known-host list come from
// EdgeTopology now, not from this payload. All-or-nothing PER set (SetLimits
// keeps the last-good set on any invalid limit); the zones map is swapped
// wholesale. An existing zone instance is reused when present so its counters
// survive the swap (SetLimits additionally carries strategies over for limits
// whose shaping config didn't change — the same counter-preservation the
// controller's reload has). Returns the first error encountered (the rest still
// apply — fail-static per set).
func (e *EdgeRateLimit) Update(generation uint64, globalDocs []string, zoneDocs map[string][]string, etag string) error {
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	// global
	if limits, err := ratelimitrule.Parse(globalDocs...); err != nil {
		note(fmt.Errorf("global: %w", err))
	} else if err := e.global.SetLimits(limits); err != nil {
		note(fmt.Errorf("global: %w", err))
	}

	// zones: reuse the existing instance per key so counters survive and a bad
	// edit keeps last-good.
	cur := e.zones.Load()
	newZones := make(map[string]*ratelimitrule.Limiter, len(zoneDocs))
	for key, docs := range zoneDocs {
		z := (*cur)[key]
		if z == nil {
			z = e.newZone(key)
		}
		if limits, err := ratelimitrule.Parse(docs...); err != nil {
			note(fmt.Errorf("zone %s: %w", key, err))
		} else if err := z.SetLimits(limits); err != nil {
			note(fmt.Errorf("zone %s: %w", key, err))
		}
		newZones[key] = z
	}
	e.zones.Store(&newZones)

	// Advance the etag + generation only on a CLEAN apply. Storing the etag on
	// a failed apply would 304 every later poll: the rejection would be warned
	// exactly once and the edge would silently keep degraded (empty or stale)
	// limits until the ConfigMap content happens to change. Withholding it
	// re-fetches and retries the input each poll — re-warning each time, so the
	// degraded state stays visible — and SetLimits' counter carry-over makes
	// the per-poll reapply harmless to live budgets. Mirrors the controller's
	// fingerprint-withhold on a rejected edit.
	if firstErr == nil {
		e.mu.Lock()
		e.etag = etag
		e.mu.Unlock()
		e.generation.Store(generation)
	}

	return firstErr
}

// Global returns the global limit-set middleware. It is a cheap pass-through
// (one atomic load) until limits are loaded.
func (e *EdgeRateLimit) Global() parapet.Middleware {
	return e.global
}

// Zone returns middleware that resolves the request to its bound rate-limit
// zone (host+path -> zoneKey -> Limiter, core ServeMux semantics) and runs that
// zone's limits. A route with no zone, or a zone with no limits, passes
// through. Host must already be normalized (host.StripPort + host.ToLower
// upstream).
func (e *EdgeRateLimit) Zone() parapet.Middleware {
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if key, ok := e.topo.resolveRLZone(r); ok {
				if zs := e.zones.Load(); zs != nil {
					if z := (*zs)[key]; z != nil {
						z.Serve(rw, r, h)
						return
					}
				}
			}
			h.ServeHTTP(rw, r)
		})
	})
}
