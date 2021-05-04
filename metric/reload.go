package metric

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var _reload reload

type reload struct {
	vec *prometheus.CounterVec
}

func init() {
	_reload.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "reload",
	}, []string{"success"})
	prom.Registry().MustRegister(_reload.vec)
}

// Reload sets reload metric
func Reload(success bool) {
	l := prometheus.Labels{
		"success": "0",
	}
	if success {
		l["success"] = "1"
	}

	counter, err := _reload.vec.GetMetricWith(l)
	if err != nil {
		return
	}
	counter.Inc()
}
