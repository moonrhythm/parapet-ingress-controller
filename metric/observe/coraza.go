package observe

import (
	"time"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var _corazaEval struct {
	vec *prometheus.HistogramVec
}

func init() {
	_corazaEval.vec = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: prom.Namespace,
		Name:      "coraza_eval_duration_seconds",
		// Reuse the CEL WAF's bucket tuning: dense below 1ms, headroom past it.
		Buckets: wafEvalBuckets,
	}, []string{"outcome", "scope"})
	prom.Registry().MustRegister(_corazaEval.vec)
}

// CorazaEval returns the corazawaf.Options.Observe hook recording per-request
// request-phase evaluation latency as parapet_coraza_eval_duration_seconds
// {outcome,scope} — the Coraza analogue of WAFEval. outcome is "pass" or
// "block"; scope is "global"/"zone". Handles are resolved once per instance, so
// the request-path hook is alloc- and lookup-free. Call only when Coraza is
// actually enabled — resolving the handles creates the (zero) series.
func CorazaEval(scope string) func(d time.Duration, blocked bool) {
	pass := _corazaEval.vec.With(prometheus.Labels{"outcome": "pass", "scope": scope})
	block := _corazaEval.vec.With(prometheus.Labels{"outcome": "block", "scope": scope})
	return func(d time.Duration, blocked bool) {
		if blocked {
			block.Observe(d.Seconds())
			return
		}
		pass.Observe(d.Seconds())
	}
}
