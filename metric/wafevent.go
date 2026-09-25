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
	pushed    prometheus.Counter
}

func init() {
	_wafEvent.dropVec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "waf_event_drops",
	}, []string{"zone"})
	_wafEvent.dropCache = newCache[string, prometheus.Counter](wafEventSizeHint)
	_wafEvent.pushed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "waf_event_pushed",
	})
	prom.Registry().MustRegister(_wafEvent.dropVec, _wafEvent.pushed)
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

// WAFEventPush counts sampled WAF match events confirmed stored by the
// collector.setWAFEvents ingest (n = events in one successful push batch).
// Together with parapet_waf_event_drops it bounds the pipeline: admitted =
// pushed + still-buffered + evicted/skipped.
func WAFEventPush(n int) {
	_wafEvent.pushed.Add(float64(n))
}
