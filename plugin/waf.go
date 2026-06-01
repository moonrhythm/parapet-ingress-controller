package plugin

import (
	"net/http"
	"strings"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/waf"
)

// WAFZone binds an ingress to a WAF zone via the parapet.moonrhythm.io/waf-zone
// annotation. The value is a zone reference: a bare id resolves to a zone in the
// ingress's own namespace; "ns/id" references a zone in another namespace.
//
// lookup resolves the registry key to the live zone WAF on the request path, so
// zone rule edits and newly-created zones take effect without a mux rebuild. A
// key that resolves to no zone (deleted / not yet created) simply passes the
// request through — the global WAF still applies upstream.
func WAFZone(lookup func(key string) *waf.WAF) Plugin {
	return func(ctx Context) {
		key, ok := ZoneKey(ctx.Ingress.Namespace, ctx.Ingress.Annotations[namespace+"/waf-zone"])
		if !ok {
			return
		}
		ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if zw := lookup(key); zw != nil {
					zw.ServeHandler(h).ServeHTTP(w, r)
					return
				}
				h.ServeHTTP(w, r)
			})
		}))
	}
}

// ZoneKey resolves a waf-zone annotation value to a zone registry key
// (<namespace>/<name>). A bare id uses the ingress's namespace; "ns/id" is used
// verbatim. Returns ok=false for an empty or malformed value.
func ZoneKey(ingressNamespace, annotation string) (key string, ok bool) {
	v := strings.TrimSpace(annotation)
	if v == "" {
		return "", false
	}
	if i := strings.IndexByte(v, '/'); i >= 0 {
		ns := strings.TrimSpace(v[:i])
		name := strings.TrimSpace(v[i+1:])
		if ns == "" || name == "" || strings.Contains(name, "/") {
			return "", false
		}
		return ns + "/" + name, true
	}
	return ingressNamespace + "/" + v, true
}
