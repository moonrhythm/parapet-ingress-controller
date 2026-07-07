package plugin

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/moonrhythm/parapet"

	"github.com/moonrhythm/parapet-ingress-controller/transformrule"
)

// Transform mounts an inline transform set carried directly in the
// parapet.moonrhythm.io/transform annotation — the same YAML document a
// transform ConfigMap holds (`transforms:` root key). It complements the
// zone reference (transform-zone): a zone is shared, ConfigMap-managed config;
// the inline set is the ingress's own, hot-reloaded the way every other inline
// annotation is — plugins re-run on each mux reload, so an annotation edit
// recompiles naturally and there is no registry to look up per request.
//
// The compile options (CEL cost limit / macro policy, GeoIP resolvers) are the
// same ones the global and zone sets use, so an inline `filter` is bounded
// identically. A set that fails to parse is logged and mounted as nothing —
// traffic passes through unmodified (the same log-and-skip failure mode as a
// bad `redirect` annotation; unlike a ConfigMap edit there is no previous
// compiled set to keep). An empty/valid-but-ruleless set mounts nothing.
func Transform(opts transformrule.Options) Plugin {
	return func(ctx Context) {
		doc := ctx.Ingress.Annotations[namespace+"/transform"]
		if strings.TrimSpace(doc) == "" {
			return
		}
		z, err := transformrule.Parse(opts, doc)
		if err != nil {
			slog.Error("plugin/transform: invalid inline transform set; passing traffic through unmodified",
				"ingress", ctx.ingressID(), "error", err)
			return
		}
		if z.Empty() {
			return
		}
		ctx.Use(parapet.MiddlewareFunc(z.ServeHandler))
	}
}

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
