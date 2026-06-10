package observe

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/moonrhythm/parapet/pkg/ratelimit"
	"github.com/prometheus/client_golang/prometheus"
)

var _ratelimit struct {
	vec *prometheus.CounterVec
}

func init() {
	_ratelimit.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "ratelimit_total",
	}, []string{"name", "result"})
	prom.Registry().MustRegister(_ratelimit.vec)
}

// RateLimit returns a ratelimit.ObserveFunc counting every limiter decision as
// parapet_ratelimit_total{name,result} (result = allowed|limited) — the same
// metric parapet's prom.RateLimit records, but with the two counter handles
// resolved here, once per limiter, so the per-request hook is alloc- and
// lookup-free (prom.RateLimit re-resolves labels on every decision). name must
// be bounded: an operator-set limiter id, never request input. The hook fires
// IN ADDITION to ExceededHandler — rejections keep their existing 503 and
// host-limit metrics.
func RateLimit(name string) ratelimit.ObserveFunc {
	allowed := _ratelimit.vec.With(prometheus.Labels{"name": name, "result": ratelimit.ResultAllowed.String()})
	limited := _ratelimit.vec.With(prometheus.Labels{"name": name, "result": ratelimit.ResultLimited.String()})
	return func(e ratelimit.Event) {
		switch e.Result {
		case ratelimit.ResultAllowed:
			allowed.Inc()
		case ratelimit.ResultLimited:
			limited.Inc()
		}
	}
}
