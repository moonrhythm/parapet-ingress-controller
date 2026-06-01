package edge

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/waf"

	"github.com/moonrhythm/parapet-ingress-controller/wafrule"
)

// EdgeWAF holds the compiled global baseline plus tenant zones fetched from the
// control plane, and exposes them as parapet middleware. It reuses
// parapet/pkg/waf (the same CEL engine the conformance corpus guards) and
// go/wafrule (the same YAML parser the controller uses), so a rule blocks
// identically at the edge and at parapet. parapet still re-runs the full WAF —
// the edge is an early-drop layer, not the authority (see EDGE.md).
//
// Eval order mirrors the controller: global first (authoritative baseline), then
// the zone bound to the request host (host-level resolution; parapet does
// path-precise resolution upstream).
type EdgeWAF struct {
	global   *waf.WAF
	zones    atomic.Pointer[map[string]*waf.WAF] // zoneKey -> compiled zone
	hostZone atomic.Pointer[map[string]string]   // host -> zoneKey

	newZone func() *waf.WAF // factory wiring Country/ASN/Logger onto a fresh zone

	mu         sync.Mutex
	etag       string
	generation uint64
}

// NewEdgeWAF builds an empty edge WAF. country/asn are the GeoIP resolvers
// (nil = request.country empty / request.asn 0); they are wired onto the global
// ruleset and every zone, so the edge — the first hop — resolves both from the
// true client IP.
func NewEdgeWAF(country func(*http.Request) string, asn func(*http.Request) int64) *EdgeWAF {
	newWAF := func() *waf.WAF {
		w := waf.New()
		w.Country = country
		w.ASN = asn
		// Edge tunables are fixed (matching the Rust edge's WafConfig::default):
		// fail-open, 5ms eval timeout (waf's own default when EvalTimeout==0).
		w.Logger = waf.LoggerFunc(func(format string, args ...any) {
			slog.Debug(fmt.Sprintf(format, args...))
		})
		return w
	}
	w := &EdgeWAF{newZone: newWAF}
	w.global = newWAF()
	empty := map[string]*waf.WAF{}
	w.zones.Store(&empty)
	emptyHZ := map[string]string{}
	w.hostZone.Store(&emptyHZ)
	return w
}

// Etag returns the ETag of the currently-loaded ruleset (sent as If-None-Match).
func (w *EdgeWAF) Etag() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.etag
}

// Update compiles and installs a fetched payload: the global ruleset, the zones,
// and the host->zone bindings. All-or-nothing PER ruleset (parapet's SetRules
// keeps the last-good ruleset on a compile error); the zones map and host->zone
// map are swapped wholesale. An existing zone instance is reused when present so
// a bad zone edit keeps its last-good rules (mirrors the controller). Returns
// the first compile error encountered (the rest still apply — fail-static per
// ruleset).
func (w *EdgeWAF) Update(generation uint64, globalYAML string, zonesYAML, hostZone map[string]string, etag string) error {
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

	hz := make(map[string]string, len(hostZone))
	for h, k := range hostZone {
		hz[h] = k
	}
	w.hostZone.Store(&hz)

	w.mu.Lock()
	w.etag = etag
	w.generation = generation
	w.mu.Unlock()

	return firstErr
}

// Global returns the global-ruleset middleware (authoritative baseline). It is a
// cheap pass-through until rules are loaded.
func (w *EdgeWAF) Global() parapet.Middleware {
	return w.global
}

// Zone returns middleware that resolves the request host to its bound zone
// (host -> zoneKey -> zone) and runs that zone's ruleset. A host with no zone, or
// a zone with no rules, passes through. Host must already be normalized
// (host.StripPort + host.ToLower upstream).
func (w *EdgeWAF) Zone() parapet.Middleware {
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if hz := w.hostZone.Load(); hz != nil {
				if key, ok := (*hz)[r.Host]; ok {
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
