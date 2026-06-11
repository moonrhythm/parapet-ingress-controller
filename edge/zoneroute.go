package edge

import (
	"log/slog"
	"net/http"
)

// zoneMatcher resolves a request to its bound zone key with the controller's
// own routing semantics: the CP ships route patterns that are byte-identical to
// the route keys the controller registers on its http.ServeMux (Prefix →
// "host/path" + "host/path/", Exact → "host/path" with the trailing slash
// stripped, ImplementationSpecific → as-is), and the matcher loads them into a
// real http.ServeMux — so precedence, subtree matching, and trailing-slash
// handling are exactly the core's. A request the mux would answer with a
// redirect (path cleaning / trailing slash) resolves to NO zone, which also
// mirrors the core: a mux-level redirect there is served before any per-route
// zone middleware runs.
//
// Shared by the edge WAF and the edge rate limiter (both bind zones through
// the same Ingress-derived patterns).
type zoneMatcher struct {
	mux *http.ServeMux
}

// zoneHandler is the sentinel registered per pattern; it only carries the zone
// key and is never actually served.
type zoneHandler struct{ key string }

func (zoneHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

// newZoneMatcher builds a matcher from the CP payload. routeZone (pattern →
// zoneKey) is preferred; when it is empty, hostZone (host → zoneKey, the
// pre-path-aware wire format an older CP serves) is synthesized into host-level
// subtree patterns ("host/"), preserving the old whole-host behavior — so a
// version-skewed CP/edge pair degrades to host-level binding, never to no
// binding.
func newZoneMatcher(routeZone, hostZone map[string]string) *zoneMatcher {
	patterns := routeZone
	if len(patterns) == 0 && len(hostZone) > 0 {
		patterns = make(map[string]string, len(hostZone))
		for host, key := range hostZone {
			patterns[host+"/"] = key
		}
	}
	mux := http.NewServeMux()
	for pattern, key := range patterns {
		func() {
			// ServeMux.Handle panics on a malformed pattern; the controller
			// skips exactly those registrations (buildRoutes recovers), so a
			// pattern the core can't route gets no zone at the edge either.
			defer func() {
				if err := recover(); err != nil {
					slog.Error("edge: register zone pattern failed", "pattern", pattern, "error", err)
				}
			}()
			mux.Handle(pattern, zoneHandler{key: key})
		}()
	}
	return &zoneMatcher{mux: mux}
}

// resolve returns the zone key bound to the request's host+path, if any. Host
// must already be normalized (host.StripPort + host.ToLower upstream — the mux
// also strips a port itself, but lowercasing is on the caller).
func (m *zoneMatcher) resolve(r *http.Request) (string, bool) {
	h, _ := m.mux.Handler(r)
	if zh, ok := h.(zoneHandler); ok {
		return zh.key, true
	}
	return "", false
}
