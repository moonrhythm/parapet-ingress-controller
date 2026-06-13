package observe

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var _cacheOverride struct {
	vec *prometheus.CounterVec
}

func init() {
	_cacheOverride.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "cache_override_total",
	}, []string{"name", "action", "result"})
	prom.Registry().MustRegister(_cacheOverride.vec)
}

// CacheOverride returns a cacherule observe hook counting every in-scope
// override decision as parapet_cache_override_total{name,action,result}
// (action = cache|bypass, result = applied|shadow|error). The three counter
// handles are resolved here, once per rule, so the per-request hook is alloc-
// and lookup-free. name and action must be bounded: an operator-set override id
// and its fixed action, never request input. A rule the filter excludes is not
// counted (only in-scope decisions appear).
func CacheOverride(name, action string) func(result string) {
	applied := _cacheOverride.vec.With(prometheus.Labels{"name": name, "action": action, "result": "applied"})
	shadow := _cacheOverride.vec.With(prometheus.Labels{"name": name, "action": action, "result": "shadow"})
	errored := _cacheOverride.vec.With(prometheus.Labels{"name": name, "action": action, "result": "error"})
	return func(result string) {
		switch result {
		case "applied":
			applied.Inc()
		case "shadow":
			shadow.Inc()
		case "error":
			errored.Inc()
		}
	}
}
