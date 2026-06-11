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
// request host (host-level resolution, same map model as the edge WAF; parapet
// does path-precise resolution upstream). Mounted AFTER the edge WAF so
// WAF-blocked traffic never burns rate budget, and BEFORE the response cache
// so edge-enforced limits apply to cache hits too.
type EdgeRateLimit struct {
	global     *ratelimitrule.Limiter
	zones      atomic.Pointer[map[string]*ratelimitrule.Limiter] // zoneKey -> compiled zone
	hostZone   atomic.Pointer[map[string]string]                 // host -> zoneKey
	knownHosts atomic.Pointer[map[string]struct{}]               // Ingress-declared hosts (host-key collapse)

	newZone func(key string) *ratelimitrule.Limiter

	generation atomic.Uint64

	mu   sync.Mutex
	etag string
}

// NewEdgeRateLimit builds an empty edge rate limiter. country/asn are the GeoIP
// resolvers (the same ones the edge WAF uses); nil makes SetLimits reject
// country/asn-keyed limits — all-or-nothing, so a geo-keyed limit set requires
// the GeoIP databases at the edge (same parity note as the WAF, see EDGE.md).
func NewEdgeRateLimit(country func(*http.Request) string, asn func(*http.Request) int64) *EdgeRateLimit {
	e := &EdgeRateLimit{}
	// knownHost reads the live Ingress-declared host set per request, so a host
	// added by a later fetch is honored without recompiling limits. A host not
	// in the set collapses (also before the first payload — there are no limits
	// to evaluate then anyway), mirroring the controller's IsKnownHost.
	knownHost := func(host string) bool {
		m := e.knownHosts.Load()
		if m == nil {
			return false
		}
		_, ok := (*m)[host]
		return ok
	}
	newLimiter := func(namePrefix string) *ratelimitrule.Limiter {
		return &ratelimitrule.Limiter{
			NamePrefix: namePrefix,
			// observe (not metric) keeps the controller's init-materialized
			// core-trust series off the edge's /metrics — same boundary as the
			// edge WAF's eval observer.
			Observe:   observe.RateLimit,
			KnownHost: knownHost,
			Country:   country,
			ASN:       asn,
		}
	}
	e.global = newLimiter("global")
	e.newZone = func(key string) *ratelimitrule.Limiter { return newLimiter("zone:" + key) }
	empty := map[string]*ratelimitrule.Limiter{}
	e.zones.Store(&empty)
	emptyHZ := map[string]string{}
	e.hostZone.Store(&emptyHZ)
	emptyHosts := map[string]struct{}{}
	e.knownHosts.Store(&emptyHosts)
	return e
}

// Etag returns the ETag of the currently-loaded config (sent as If-None-Match).
func (e *EdgeRateLimit) Etag() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.etag
}

// Update compiles and installs a fetched payload: the global limit set, the
// zones, the host->zone bindings, and the known-host list. All-or-nothing PER
// set (SetLimits keeps the last-good set on any invalid limit); the zones map,
// host->zone map, and known-host set are swapped wholesale. An existing zone
// instance is reused when present so its counters survive the swap (SetLimits
// additionally carries strategies over for limits whose shaping config didn't
// change — the same counter-preservation the controller's reload has). Returns
// the first error encountered (the rest still apply — fail-static per set).
func (e *EdgeRateLimit) Update(generation uint64, globalDocs []string, zoneDocs map[string][]string, hostZone map[string]string, hosts []string, etag string) error {
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	// Swap the known-host set BEFORE applying limits: SetLimits compiles
	// against the live closure, and a request racing the swap just collapses
	// (or not) against whichever set is current — both are sound snapshots.
	hs := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		hs[h] = struct{}{}
	}
	e.knownHosts.Store(&hs)

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

	hz := make(map[string]string, len(hostZone))
	for h, k := range hostZone {
		hz[h] = k
	}
	e.hostZone.Store(&hz)

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

// Zone returns middleware that resolves the request host to its bound
// rate-limit zone (host -> zoneKey -> Limiter) and runs that zone's limits. A
// host with no zone, or a zone with no limits, passes through. Host must
// already be normalized (host.StripPort + host.ToLower upstream).
func (e *EdgeRateLimit) Zone() parapet.Middleware {
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if hz := e.hostZone.Load(); hz != nil {
				if key, ok := (*hz)[r.Host]; ok {
					if zs := e.zones.Load(); zs != nil {
						if z := (*zs)[key]; z != nil {
							z.Serve(rw, r, h)
							return
						}
					}
				}
			}
			h.ServeHTTP(rw, r)
		})
	})
}
