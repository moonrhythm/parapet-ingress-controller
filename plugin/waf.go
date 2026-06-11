package plugin

import (
	"net/http"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/waf"

	"github.com/moonrhythm/parapet-ingress-controller/metric"
)

// WAFZone binds an ingress to a WAF zone via the parapet.moonrhythm.io/waf-zone
// annotation. The value is a zone reference: a bare id resolves to a zone in the
// ingress's own namespace; "ns/id" references a zone in another namespace.
//
// lookup resolves the registry key to the live zone WAF on the request path, so
// zone rule edits and newly-created zones take effect without a mux rebuild. A
// key that resolves to no zone (deleted / not yet created) simply passes the
// request through — the global WAF still applies upstream.
//
// skip, when non-nil, reports requests whose WAF validation already happened at
// a trusted upstream hop (WAF_VALIDATED_PROXY — the edge runs the same zone
// rules); they bypass the zone ruleset, mirroring the global WAF's skip.
func WAFZone(lookup func(key string) *waf.WAF, skip func(*http.Request) bool) Plugin {
	return func(ctx Context) {
		key, ok := ZoneKey(ctx.Ingress.Namespace, ctx.Ingress.Annotations[namespace+"/waf-zone"])
		if !ok {
			return
		}
		ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if skip != nil && skip(r) {
					metric.WAFSkip("zone")
					h.ServeHTTP(w, r)
					return
				}
				if zw := lookup(key); zw != nil {
					zw.ServeHandler(h).ServeHTTP(w, r)
					return
				}
				h.ServeHTTP(w, r)
			})
		}))
	}
}
