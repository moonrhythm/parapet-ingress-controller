package metric

import (
	"strconv"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

const corazaSizeHint = 200

var _coraza corazaMetric

type corazaMetric struct {
	vec   *prometheus.CounterVec
	cache *cache[corazaKey, prometheus.Counter]
}

// corazaKey is the cache key for the per-(rule,severity,scope) counter handle.
// All three are bounded: rule IDs come from a fixed operator ruleset (e.g. the
// OWASP CRS), severity is Coraza's 8-value enum, and scope is global|zone — so
// request input can't inflate the series.
type corazaKey struct {
	ruleID   string
	severity string
	scope    string
}

func init() {
	_coraza.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "coraza_matches",
	}, []string{"rule_id", "severity", "scope"})
	_coraza.cache = newCache[corazaKey, prometheus.Counter](corazaSizeHint)
	prom.Registry().MustRegister(_coraza.vec)
}

// CorazaMatch increments the Coraza match counter for a rule that fired. scope is
// "global" or "zone".
func CorazaMatch(ruleID int, severity, scope string) {
	id := strconv.Itoa(ruleID)
	_coraza.cache.getOrCreate(corazaKey{ruleID: id, severity: severity, scope: scope}, func() prometheus.Counter {
		return _coraza.vec.With(prometheus.Labels{
			"rule_id":  id,
			"severity": severity,
			"scope":    scope,
		})
	}).Inc()
}
