package metric

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var _backendBadAddr backendBadAddrMetric

type backendBadAddrMetric struct {
	vec   *prometheus.CounterVec
	cache *cache[backendKey, prometheus.Counter]
}

func init() {
	labels := []string{"service_type", "service_namespace", "service_name"}
	_backendBadAddr.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "backend_bad_addr",
		Help:      "Times an upstream address was marked bad (dial failure or post-connect no-response).",
	}, labels)
	_backendBadAddr.cache = newCache[backendKey, prometheus.Counter](backendSizeHint)
	prom.Registry().MustRegister(_backendBadAddr.vec)
}

// BackendBadAddr counts one mark-bad event, attributed to the destination
// Service (not the dialed pod IP) — see backendKey for why.
func BackendBadAddr(serviceType, serviceNamespace, serviceName string) {
	_backendBadAddr.cache.getOrCreate(backendKey{
		serviceType:      serviceType,
		serviceNamespace: serviceNamespace,
		serviceName:      serviceName,
	}, func() prometheus.Counter {
		return _backendBadAddr.vec.With(prometheus.Labels{
			"service_type":      serviceType,
			"service_namespace": serviceNamespace,
			"service_name":      serviceName,
		})
	}).Inc()
}
