package metric

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

const wafEventSizeHint = 100

var _wafEvent wafEventMetric

type wafEventMetric struct {
	dropVec   *prometheus.CounterVec
	dropCache *cache[string, prometheus.Counter]
}

func init() {
	_wafEvent.dropVec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "waf_event_drops",
	}, []string{"zone"})
	_wafEvent.dropCache = newCache[string, prometheus.Counter](wafEventSizeHint)
	prom.Registry().MustRegister(_wafEvent.dropVec)
}

// WAFEventDrop counts a sampled WAF match event that was dropped — by the
// per-(zone, rule) / per-zone sampling caps or by ring overwrite — so we can
// see when sampling is active. zone is the registry key <namespace>/<name>:
// bounded by the set of configured zone ConfigMaps, not by request input.
func WAFEventDrop(zone string) {
	_wafEvent.dropCache.getOrCreate(zone, func() prometheus.Counter {
		return _wafEvent.dropVec.With(prometheus.Labels{"zone": zone})
	}).Inc()
}
