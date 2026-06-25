package observe

import (
	"sync"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/moonrhythm/parapet/pkg/waf"
	"github.com/prometheus/client_golang/prometheus"
)

var _wafEval struct {
	vec *prometheus.HistogramVec
}

// _wafMatch is registered LAZILY (first WAFMatch call), NOT in init(): the
// controller imports this package for WAFEval but records matches through
// metric.WAFMatch, whose init already registers parapet_waf_matches on the shared
// registry — eager registration here would duplicate-register and panic at
// startup. Only a binary that actually wires the OnMatch hook (the edge) mints
// the series.
var _wafMatch struct {
	once sync.Once
	vec  *prometheus.CounterVec
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

// WAFMatch returns a hook for waf.WAF.OnMatch counting every rule that fires as
// parapet_waf_matches{rule_id,action,scope} — the SAME metric the controller's
// metric.WAFMatch records, so an edge's matches aggregate with the core's on one
// dashboard. scope is "global"/"zone"; all three labels are bounded (rule_id and
// action come from the operator's ruleset, scope is caller-fixed — never request
// input). See _wafMatch for why registration is lazy.
//
// Handles can't be pre-resolved the way WAFEval does — rule IDs aren't known
// until a rule fires — so each event resolves through CounterVec.With (internally
// locked+cached). Matches are rare relative to evals, so this lookup is off the
// hot path. Call only when the WAF is actually enabled.
func WAFMatch(scope string) func(waf.MatchEvent) {
	_wafMatch.once.Do(func() {
		_wafMatch.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: prom.Namespace,
			Name:      "waf_matches",
		}, []string{"rule_id", "action", "scope"})
		prom.Registry().MustRegister(_wafMatch.vec)
	})
	return func(ev waf.MatchEvent) {
		_wafMatch.vec.With(prometheus.Labels{
			"rule_id": ev.RuleID,
			"action":  ev.Action.String(),
			"scope":   scope,
		}).Inc()
	}
}
