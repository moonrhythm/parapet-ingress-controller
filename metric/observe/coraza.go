package observe

import (
	"strconv"
	"sync"
	"time"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var _corazaEval struct {
	vec *prometheus.HistogramVec
}

// _corazaMatch registers lazily for the same reason as _wafMatch: the controller
// records Coraza matches via metric.CorazaMatch (registered in metric's init), so
// eager registration here would duplicate-register and panic. Only the edge wires
// the hook.
var _corazaMatch struct {
	once sync.Once
	vec  *prometheus.CounterVec
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

// CorazaMatch returns the corazawaf.Options.OnMatch hook counting every rule that
// fires as parapet_coraza_matches{rule_id,severity,scope} — the Coraza analogue
// of WAFMatch and the same metric the controller's metric.CorazaMatch records.
// scope is "global"/"zone"; all three labels are bounded (rule_id and severity
// come from the operator's ruleset, scope is caller-fixed). It takes the rule id
// and severity raw rather than a corazawaf.MatchEvent so observe stays decoupled
// from corazawaf (mirroring CorazaEval's raw signature). Lazy registration, same
// reasoning as WAFMatch; call only when Coraza is enabled.
func CorazaMatch(scope string) func(ruleID int, severity string) {
	_corazaMatch.once.Do(func() {
		_corazaMatch.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: prom.Namespace,
			Name:      "coraza_matches",
		}, []string{"rule_id", "severity", "scope"})
		prom.Registry().MustRegister(_corazaMatch.vec)
	})
	return func(ruleID int, severity string) {
		_corazaMatch.vec.With(prometheus.Labels{
			"rule_id":  strconv.Itoa(ruleID),
			"severity": severity,
			"scope":    scope,
		}).Inc()
	}
}
