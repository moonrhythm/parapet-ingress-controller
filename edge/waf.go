package edge

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/waf"

	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
	"github.com/moonrhythm/parapet-ingress-controller/wafclaim"
	"github.com/moonrhythm/parapet-ingress-controller/wafrule"
)

// EdgeWAF holds the compiled global baseline plus tenant zones fetched from the
// control plane, and exposes them as parapet middleware. It reuses
// parapet/pkg/waf (the same CEL engine the conformance corpus guards) and
// go/wafrule (the same YAML parser the controller uses), so a rule blocks
// identically at the edge and at parapet. parapet still re-runs the full WAF —
// the edge is an early-drop layer, not the authority (see EDGE.md).
//
// Eval order mirrors the controller: global first (authoritative baseline),
// then the zone bound to the request route. Zone resolution is PATH-AWARE: the
// CP ships the controller's own route patterns (host+path, per PathType), and
// the matcher runs them through a real http.ServeMux — so two ingresses sharing
// a host with different paths and different zones resolve exactly as they do at
// the core.
type EdgeWAF struct {
	global  *waf.WAF
	zones   atomic.Pointer[map[string]*waf.WAF] // zoneKey -> compiled zone
	matcher atomic.Pointer[zoneMatcher]         // host+path -> zoneKey (core ServeMux semantics)

	newZone func() *waf.WAF // factory wiring Country/ASN/Logger onto a fresh zone

	// generation of the currently-loaded snapshot (0 until the first CP fetch
	// applies). Atomic: ClaimStamp reads it per request.
	generation atomic.Uint64

	mu   sync.Mutex
	etag string
}

// NewEdgeWAF builds an empty edge WAF. country/asn are the GeoIP resolvers
// (nil = request.country empty / request.asn 0); they are wired onto the global
// ruleset and every zone, so the edge — the first hop — resolves both from the
// true client IP.
func NewEdgeWAF(country func(*http.Request) string, asn func(*http.Request) int64) *EdgeWAF {
	newWAF := func(scope string) *waf.WAF {
		w := waf.New()
		w.Country = country
		w.ASN = asn
		// Edge tunables are fixed: fail-open, 5ms eval timeout (waf's own
		// default when EvalTimeout==0).
		w.Logger = waf.LoggerFunc(func(format string, args ...any) {
			slog.Debug(fmt.Sprintf(format, args...))
		})
		// Eval latency + outcome per evaluated request (the no-rules pass-through
		// before rules load doesn't fire it), same metric as the controller.
		// observe (not metric) keeps the controller's init-materialized
		// core-trust series off the edge's /metrics.
		w.Observe = observe.WAFEval(scope)
		// Per-rule match counter (parapet_waf_matches), same metric as the
		// controller — so an edge's matches aggregate with the core's. Fires only
		// on a match, which the eval-outcome histogram can't attribute to a rule.
		w.OnMatch = observe.WAFMatch(scope)
		return w
	}
	w := &EdgeWAF{newZone: func() *waf.WAF { return newWAF("zone") }}
	w.global = newWAF("global")
	empty := map[string]*waf.WAF{}
	w.zones.Store(&empty)
	w.matcher.Store(newZoneMatcher(nil, nil))
	return w
}

// Etag returns the ETag of the currently-loaded ruleset (sent as If-None-Match).
func (w *EdgeWAF) Etag() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.etag
}

// Update compiles and installs a fetched payload: the global ruleset, the
// zones, and the zone bindings. routeZone is the path-aware binding (route
// pattern -> zoneKey); hostZone is the legacy host-level binding an older CP
// serves, used only when routeZone is empty (see newZoneMatcher). All-or-nothing
// PER ruleset (parapet's SetRules keeps the last-good ruleset on a compile
// error); the zones map and the matcher are swapped wholesale. An existing zone
// instance is reused when present so a bad zone edit keeps its last-good rules
// (mirrors the controller). Returns the first compile error encountered (the
// rest still apply — fail-static per ruleset).
func (w *EdgeWAF) Update(generation uint64, globalYAML string, zonesYAML, routeZone, hostZone map[string]string, etag string) error {
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	// global
	if rules, err := wafrule.Parse(globalYAML); err != nil {
		note(fmt.Errorf("global: %w", err))
	} else if err := w.global.SetRules(rules); err != nil {
		note(fmt.Errorf("global: %w", err))
	}

	// zones: reuse the existing instance per key so a bad edit keeps last-good.
	cur := w.zones.Load()
	newZones := make(map[string]*waf.WAF, len(zonesYAML))
	for key, yaml := range zonesYAML {
		z := (*cur)[key]
		if z == nil {
			z = w.newZone()
		}
		if rules, err := wafrule.Parse(yaml); err != nil {
			note(fmt.Errorf("zone %s: %w", key, err))
		} else if err := z.SetRules(rules); err != nil {
			note(fmt.Errorf("zone %s: %w", key, err))
		}
		newZones[key] = z
	}
	w.zones.Store(&newZones)

	w.matcher.Store(newZoneMatcher(routeZone, hostZone))

	// Advance the etag + generation only on a CLEAN apply. Storing the etag on
	// a failed compile would 304 every later poll and the bad input would never
	// be retried (the core deliberately withholds its fingerprint on a rejected
	// edit for the same reason); the cost is one re-fetch+recompile per poll
	// until the input is fixed. Holding the generation back keeps the claim
	// honest: at boot a bad FIRST snapshot leaves generation 0, so ClaimStamp
	// never claims validation for the empty boot ruleset — and at steady state
	// the claim keeps carrying the last cleanly-applied generation.
	if firstErr == nil {
		w.mu.Lock()
		w.etag = etag
		w.mu.Unlock()
		w.generation.Store(generation)
	}

	return firstErr
}

// Global returns the global-ruleset middleware (authoritative baseline). It is a
// cheap pass-through until rules are loaded.
func (w *EdgeWAF) Global() parapet.Middleware {
	return w.global
}

// ClaimStamp returns middleware that stamps the WAF-validated claim
// (wafclaim.Header) on requests forwarded to the core. Mount it AFTER Global()
// and Zone(): a request reaching it has passed both rulesets, so the claim
// asserts "this edge's WAF evaluated the request against a live snapshot". It
// stamps only once a CP snapshot has applied CLEANLY (generation > 0; Update
// holds the generation back on a compile failure) — an edge that booted while
// the CP was unreachable, or whose first snapshot was rejected, is serving the
// empty initial ruleset and must not claim validation, so the core keeps
// evaluating its traffic (WAF_VALIDATED_PROXY requires the claim in addition
// to peer trust). After a clean apply the claim reflects last-good fail-static
// state, mirroring the core's own keep-last-good posture. Self-contained
// either way: gen > 0 overwrites any inbound value (Set, not Add), gen == 0
// deletes it — so even without StripWAFClaim mounted upstream a client value
// never survives this middleware.
func (w *EdgeWAF) ClaimStamp() parapet.Middleware {
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if gen := w.generation.Load(); gen > 0 {
				r.Header.Set(wafclaim.Header, strconv.FormatUint(gen, 10))
			} else {
				r.Header.Del(wafclaim.Header)
			}
			h.ServeHTTP(rw, r)
		})
	})
}

// StripWAFClaim returns middleware that removes any client-supplied
// WAF-validated claim. Mounted UNCONDITIONALLY (even with
// EDGE_WAF_ENABLED=false) and before the WAF, so a client can never smuggle a
// claim through this edge to the core — a WAF-disabled edge forwards claimless
// requests and the core evaluates them — and CEL rules never see a spoofed
// value in request.headers.
func StripWAFClaim() parapet.Middleware {
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			r.Header.Del(wafclaim.Header)
			h.ServeHTTP(rw, r)
		})
	})
}

// Zone returns middleware that resolves the request to its bound zone
// (host+path -> zoneKey -> zone, core ServeMux semantics) and runs that zone's
// ruleset. A route with no zone, or a zone with no rules, passes through. Host
// must already be normalized (host.StripPort + host.ToLower upstream).
func (w *EdgeWAF) Zone() parapet.Middleware {
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if m := w.matcher.Load(); m != nil {
				if key, ok := m.resolve(r); ok {
					if zs := w.zones.Load(); zs != nil {
						if z := (*zs)[key]; z != nil {
							z.ServeHandler(h).ServeHTTP(rw, r)
							return
						}
					}
				}
			}
			h.ServeHTTP(rw, r)
		})
	})
}
