package edge

import (
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/moonrhythm/parapet"

	"github.com/moonrhythm/parapet-ingress-controller/corazawaf"
	"github.com/moonrhythm/parapet-ingress-controller/geoip"
	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
)

// EdgeCoraza holds the compiled global Coraza baseline plus tenant zones fetched
// from the control plane, and exposes them as parapet middleware. It reuses the
// corazawaf engine (the same OWASP Coraza the controller runs) so a SecLang rule
// blocks identically at the edge and at the core. It runs as DEFENSE-IN-DEPTH:
// unlike the CEL WAF there is no validated-proxy claim — the core always re-runs
// its own Coraza ruleset (parapet stays authoritative, see EDGE.md).
//
// Zone resolution is PATH-AWARE and reuses the same zoneMatcher as the edge WAF:
// the CP ships the controller's own route patterns (host+path, per PathType) and
// the matcher runs them through a real http.ServeMux. There is no legacy
// host-level binding — Coraza is a new feature with no old edges.
type EdgeCoraza struct {
	global  *corazawaf.Instance
	zones   atomic.Pointer[map[string]*corazawaf.Instance] // zoneKey -> compiled zone
	matcher atomic.Pointer[zoneMatcher]                    // host+path -> zoneKey (core ServeMux semantics)

	newZone func() *corazawaf.Instance

	// generation of the currently-loaded snapshot (0 until the first clean CP
	// apply). Atomic; reserved for parity/observability.
	generation atomic.Uint64

	mu   sync.Mutex
	etag string
}

// NewEdgeCoraza builds an empty edge Coraza. rootFS resolves Include directives
// (wire the embedded OWASP CRS so a ruleset can `Include @owasp_crs`);
// requestBodyLimit caps request-body inspection (<= 0 = URI + headers only). The
// true client IP is resolved with the same precedence the edge WAF uses.
func NewEdgeCoraza(rootFS fs.FS, requestBodyLimit int) *EdgeCoraza {
	clientIP := func(r *http.Request) string {
		if ip := geoip.ClientIP(r); ip != nil {
			return ip.String()
		}
		return ""
	}
	newInstance := func(scope string) *corazawaf.Instance {
		return corazawaf.New(corazawaf.Options{
			RootFS:           rootFS,
			RequestBodyLimit: requestBodyLimit,
			ClientIP:         clientIP,
			Observe:          observe.CorazaEval(scope),
			// Edge logs matches at debug only; it deliberately stays off the metric
			// package (observe keeps the edge's /metrics free of the controller's
			// core-trust series). Per-rule match counters are the core's job.
			OnMatch: func(ev corazawaf.MatchEvent) {
				slog.Debug("edge coraza match", "scope", scope, "rule", ev.RuleID,
					"disruptive", ev.Disruptive, "uri", ev.URI, "message", ev.Message)
			},
		})
	}
	w := &EdgeCoraza{newZone: func() *corazawaf.Instance { return newInstance("zone") }}
	w.global = newInstance("global")
	empty := map[string]*corazawaf.Instance{}
	w.zones.Store(&empty)
	w.matcher.Store(newZoneMatcher(nil, nil))
	return w
}

// Etag returns the ETag of the currently-loaded ruleset (sent as If-None-Match).
func (w *EdgeCoraza) Etag() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.etag
}

// Update compiles and installs a fetched payload: the global ruleset, the zones,
// and the path-aware route→zone binding. All-or-nothing PER ruleset
// (corazawaf.SetDirectives keeps the last-good instance on a compile error); the
// zones map and matcher are swapped wholesale. An existing zone instance is
// reused when present so a bad zone edit keeps its last-good rules (mirrors the
// edge WAF). Returns the first compile error encountered (the rest still apply).
func (w *EdgeCoraza) Update(generation uint64, globalDirectives string, zonesDirectives, routeZone map[string]string, etag string) error {
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	if err := w.global.SetDirectives(globalDirectives); err != nil {
		note(fmt.Errorf("global: %w", err))
	}

	cur := w.zones.Load()
	newZones := make(map[string]*corazawaf.Instance, len(zonesDirectives))
	for key, directives := range zonesDirectives {
		z := (*cur)[key]
		if z == nil {
			z = w.newZone()
		}
		if err := z.SetDirectives(directives); err != nil {
			note(fmt.Errorf("zone %s: %w", key, err))
		}
		newZones[key] = z
	}
	w.zones.Store(&newZones)

	w.matcher.Store(newZoneMatcher(routeZone, nil))

	// Advance the etag + generation only on a CLEAN apply (a failed compile would
	// 304 every later poll and never retry the bad input — same reasoning as the
	// edge WAF).
	if firstErr == nil {
		w.mu.Lock()
		w.etag = etag
		w.mu.Unlock()
		w.generation.Store(generation)
	}

	return firstErr
}

// Global returns the global-ruleset middleware. A cheap pass-through until rules
// are loaded.
func (w *EdgeCoraza) Global() parapet.Middleware {
	return w.global
}

// Zone returns middleware that resolves the request to its bound zone (host+path
// -> zoneKey -> zone, core ServeMux semantics) and runs that zone's ruleset. A
// route with no zone, or a zone with no rules, passes through. Host must already
// be normalized (host.StripPort + host.ToLower upstream).
func (w *EdgeCoraza) Zone() parapet.Middleware {
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
