package observe

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/moonrhythm/parapet/pkg/waf"
	"github.com/prometheus/client_golang/prometheus"
)

var _wafEval struct {
	vec *prometheus.HistogramVec
}

// wafEvalBuckets match parapet's prom.WAF tuning: dense below 1ms where the bulk
// of evals sit, an edge ON the 5ms default EvalTimeout (the SLO line), and
// 10/25ms headroom for raised timeouts. prometheus.DefBuckets starts AT 5ms, so
// it would collapse the whole distribution into one bucket.
var wafEvalBuckets = []float64{
	0.000025, 0.00005, 0.0001, 0.00025, 0.0005, // 25us..500us
	0.001, 0.0025, 0.005, // 1ms..5ms (default EvalTimeout)
	0.01, 0.025, // past-timeout tail
}

func init() {
	_wafEval.vec = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: prom.Namespace,
		Name:      "waf_eval_duration_seconds",
		Buckets:   wafEvalBuckets,
	}, []string{"outcome", "scope"})
	prom.Registry().MustRegister(_wafEval.vec)
}

// WAFEval returns a waf.ObserveFunc recording per-request rule-eval latency as
// parapet_waf_eval_duration_seconds{outcome,scope} — parapet's prom.WAF metric
// plus the scope label ("global"/"zone"), matching parapet_waf_matches. Unlike
// OnMatch it fires once per evaluated request, so the silent-majority no-match
// path and the WAF's per-request overhead are visible. Both labels are bounded:
// outcome is waf's closed four-value set and scope is caller-fixed. Handles are
// resolved here, once per WAF instance, so the hook itself is alloc- and
// lookup-free on the request path. Call only when the WAF is actually enabled —
// resolving the handles creates the (zero) series.
func WAFEval(scope string) waf.ObserveFunc {
	obs := func(o waf.Outcome) prometheus.Observer {
		return _wafEval.vec.With(prometheus.Labels{"outcome": o.String(), "scope": scope})
	}
	handles := [...]prometheus.Observer{
		waf.OutcomePass:  obs(waf.OutcomePass),
		waf.OutcomeAllow: obs(waf.OutcomeAllow),
		waf.OutcomeBlock: obs(waf.OutcomeBlock),
		waf.OutcomeError: obs(waf.OutcomeError),
	}
	return func(ev waf.EvalEvent) {
		// An outcome outside the known set is dropped rather than minting an
		// "unknown" series from request-path input.
		if int(ev.Outcome) < len(handles) {
			handles[ev.Outcome].Observe(ev.Duration.Seconds())
		}
	}
}
