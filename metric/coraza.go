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

// corazaKey is the cache key for the per-(rule,severity,scope,zone) counter
// handle. All four are bounded: rule IDs come from a fixed operator ruleset
// (e.g. the OWASP CRS), severity is Coraza's 8-value enum, scope is
// global|zone, and zone is a zone-registry key (one per zone ConfigMap; "" for
// scope=global) — so request input can't inflate the series.
type corazaKey struct {
	ruleID   string
	severity string
	scope    string
	zone     string
}

func init() {
	_coraza.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "coraza_matches",
	}, []string{"rule_id", "severity", "scope", "zone"})
	_coraza.cache = newCache[corazaKey, prometheus.Counter](corazaSizeHint)
	prom.Registry().MustRegister(_coraza.vec)
}

// CorazaMatch increments the Coraza match counter for a rule that fired. scope is
// "global" or "zone"; zone is the zone-registry key (<namespace>/<name>) that
// makes CRS matches attributable per zone — Coraza rule ids are shared by every
// zone, unlike the CEL WAF's operator-prefixed ids — and "" for scope=global.
func CorazaMatch(ruleID int, severity, scope, zone string) {
	id := strconv.Itoa(ruleID)
	_coraza.cache.getOrCreate(corazaKey{ruleID: id, severity: severity, scope: scope, zone: zone}, func() prometheus.Counter {
		return _coraza.vec.With(prometheus.Labels{
			"rule_id":  id,
			"severity": severity,
			"scope":    scope,
			"zone":     zone,
		})
	}).Inc()
}
