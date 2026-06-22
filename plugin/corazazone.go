package plugin

import (
	"net/http"

	"github.com/moonrhythm/parapet"

	"github.com/moonrhythm/parapet-ingress-controller/corazawaf"
)

// CorazaZone binds an ingress to a Coraza zone via the
// parapet.moonrhythm.io/coraza-zone annotation. The value is a zone reference: a
// bare id resolves to a zone in the ingress's own namespace; "ns/id" references a
// zone in another namespace — the same resolver the CEL waf-zone uses.
//
// lookup resolves the registry key to the live zone instance on the request
// path, so zone rule edits and newly-created zones take effect without a mux
// rebuild. A key that resolves to no zone (deleted / not yet created), or a zone
// with no rules loaded, simply passes the request through — the global Coraza
// still applies upstream.
func CorazaZone(lookup func(key string) *corazawaf.Instance) Plugin {
	return func(ctx Context) {
		key, ok := ZoneKey(ctx.Ingress.Namespace, ctx.Ingress.Annotations[namespace+"/coraza-zone"])
		if !ok {
			return
		}
		ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if zc := lookup(key); zc != nil {
					zc.ServeHandler(h).ServeHTTP(w, r)
					return
				}
				h.ServeHTTP(w, r)
			})
		}))
	}
}
