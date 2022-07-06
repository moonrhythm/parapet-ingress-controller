package metric

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var _hostRatelimit hostRatelimit

type hostRatelimit struct {
	vec *prometheus.CounterVec
}

func init() {
	_hostRatelimit.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "host_ratelimit_requests",
	}, []string{"host"})
	prom.Registry().MustRegister(_hostRatelimit.vec)
}

// HostRatelimit increments the host ratelimit counter
func HostRatelimit(host string) {
	l := prometheus.Labels{
		"host": host,
	}

	counter, err := _hostRatelimit.vec.GetMetricWith(l)
	if err != nil {
		return
	}
	counter.Inc()
}
