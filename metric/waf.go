package metric

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

const wafSizeHint = 100

var _waf wafMetric

type wafMetric struct {
	vec   *prometheus.CounterVec
	cache *cache[wafKey, prometheus.Counter]

	skipVec   *prometheus.CounterVec
	skipCache *cache[string, prometheus.Counter]
}

// wafKey is the cache key for the per-(rule,action,scope) counter handle. All
// three labels are bounded: rule IDs are operator-defined (a fixed ruleset),
// action is one of log|allow|block, and scope is global|zone — so this cannot
// be inflated into unbounded series by request input.
type wafKey struct {
	ruleID string
	action string
	scope  string
}

func init() {
	_waf.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "waf_matches",
	}, []string{"rule_id", "action", "scope"})
	_waf.cache = newCache[wafKey, prometheus.Counter](wafSizeHint)
	prom.Registry().MustRegister(_waf.vec)

	_waf.skipVec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "waf_skips",
	}, []string{"scope"})
	_waf.skipCache = newCache[string, prometheus.Counter](2)
	prom.Registry().MustRegister(_waf.skipVec)
}

// WAFSkip counts a request whose WAF evaluation was skipped because the peer
// already validated it (WAF_VALIDATED_PROXY). scope is "global" or "zone", so
// the label set is bounded.
func WAFSkip(scope string) {
	_waf.skipCache.getOrCreate(scope, func() prometheus.Counter {
		return _waf.skipVec.With(prometheus.Labels{"scope": scope})
	}).Inc()
}

// WAFMatch increments the WAF match counter for a rule that fired. scope is
// "global" or "zone".
func WAFMatch(ruleID, action, scope string) {
	_waf.cache.getOrCreate(wafKey{ruleID: ruleID, action: action, scope: scope}, func() prometheus.Counter {
		return _waf.vec.With(prometheus.Labels{
			"rule_id": ruleID,
			"action":  action,
			"scope":   scope,
		})
	}).Inc()
}
