package plugin

import (
	"net/http"

	"github.com/moonrhythm/parapet"

	"github.com/moonrhythm/parapet-ingress-controller/transformrule"
)

// TransformZone binds an ingress to a transform zone via the
// parapet.moonrhythm.io/transform-zone annotation. The value is a zone
// reference: a bare id resolves to a zone in the ingress's own namespace;
// "ns/id" references a zone in another namespace — the same resolver the CEL
// waf-zone uses. A transform zone is stateless, operator-authored config (like a
// WAF zone, unlike a rate-limit zone's shared counters), so a cross-namespace
// reference is harmless and honored.
//
// lookup resolves the registry key to the live zone on the request path, so zone
// rule edits and newly-created zones take effect without a mux rebuild. A key
// that resolves to no zone (deleted / not yet created / rejected first config)
// simply passes the request through unmodified — a safe no-op, never a break.
func TransformZone(lookup func(key string) *transformrule.Zone) Plugin {
	return func(ctx Context) {
		key, ok := ZoneKey(ctx.Ingress.Namespace, ctx.Ingress.Annotations[namespace+"/transform-zone"])
		if !ok {
			return
		}
		ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if z := lookup(key); z != nil {
					z.ServeHandler(h).ServeHTTP(w, r)
					return
				}
				h.ServeHTTP(w, r)
			})
		}))
	}
}
