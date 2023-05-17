package metric

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var _reload reload

type reload struct {
	vec *prometheus.CounterVec

	successCounter prometheus.Counter
	failCounter    prometheus.Counter
}

func init() {
	_reload.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "reload",
	}, []string{"success"})
	_reload.successCounter, _ = _reload.vec.GetMetricWith(prometheus.Labels{"success": "1"})
	_reload.failCounter, _ = _reload.vec.GetMetricWith(prometheus.Labels{"success": "0"})
	prom.Registry().MustRegister(_reload.vec)
}

// Reload sets reload metric
func Reload(success bool) {
	if !success {
		_reload.failCounter.Inc()
		return
	}
	_reload.successCounter.Inc()
}
