package plugin

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/moonrhythm/parapet"

	"github.com/moonrhythm/parapet-ingress-controller/ratelimitrule"
)

// RateLimitZone binds an ingress to a rate-limit zone via the
// parapet.moonrhythm.io/ratelimit-zone annotation. The value is a zone id in
// the ingress's OWN namespace ("ns/id" is accepted only when ns is that same
// namespace).
//
// This is deliberately narrower than waf-zone, which honors cross-namespace
// references: a WAF zone is stateless config, harmless to its owner wherever
// it's applied, but a rate-limit zone carries shared counter state — honoring
// a cross-namespace reference would let any tenant bind another tenant's zone
// and burn its per-key budgets (a cross-tenant denial of service). A
// cross-namespace reference is logged and ignored.
//
// lookup resolves the registry key to the live zone on the request path, so
// zone limit edits and newly-created zones take effect without a mux rebuild.
// A key that resolves to no zone (deleted / not yet created / rejected first
// config) passes the request through unlimited — the global limits still apply
// upstream.
func RateLimitZone(lookup func(key string) *ratelimitrule.Limiter) Plugin {
	return func(ctx Context) {
		key, ok := ZoneKey(ctx.Ingress.Namespace, ctx.Ingress.Annotations[namespace+"/ratelimit-zone"])
		if !ok {
			return
		}
		if !strings.HasPrefix(key, ctx.Ingress.Namespace+"/") {
			slog.Warn("plugin/RateLimitZone: cross-namespace ratelimit-zone is not honored (zones carry shared counter state); ignoring",
				"ingress", ctx.ingressID(), "zone", key)
			return
		}
		ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if z := lookup(key); z != nil {
					z.Serve(w, r, h)
					return
				}
				h.ServeHTTP(w, r)
			})
		}))
	}
}
