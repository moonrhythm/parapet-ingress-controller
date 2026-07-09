package metric

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var _ws wsMetric

type wsMetric struct {
	vec      *prometheus.CounterVec
	cache    *cache[string, prometheus.Counter]
	active   prometheus.Gauge
	h2c      *prometheus.CounterVec
	h2cCache *cache[string, prometheus.Counter]
}

func init() {
	_ws.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "ws_tunnels",
	}, []string{"result"})
	// result is one of a fixed set (tunneled|refused|upstream_error|bad_protocol),
	// so the series is bounded and the cache never grows past it.
	_ws.cache = newCache[string, prometheus.Counter](4)
	prom.Registry().MustRegister(_ws.vec)

	_ws.active = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "ws_tunnel_active",
	})
	prom.Registry().MustRegister(_ws.active)

	_ws.h2c = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "ws_upstream_h2c",
	}, []string{"result"})
	// result is one of a fixed set (ok|not_supported|error), so the series is
	// bounded and the cache never grows past it.
	_ws.h2cCache = newCache[string, prometheus.Counter](3)
	prom.Registry().MustRegister(_ws.h2c)
}

// WSTunnel counts an extended-CONNECT WebSocket handshake by its outcome. result
// is one of tunneled|refused|upstream_error|bad_protocol.
func WSTunnel(result string) {
	_ws.cache.getOrCreate(result, func() prometheus.Counter {
		return _ws.vec.With(prometheus.Labels{"result": result})
	}).Inc()
}

// WSTunnelActiveInc / WSTunnelActiveDec bracket a live spliced session.
func WSTunnelActiveInc() { _ws.active.Inc() }
func WSTunnelActiveDec() { _ws.active.Dec() }

// WSUpstreamH2C counts a core→pod extended-CONNECT attempt by its outcome. result
// is one of ok|not_supported|error.
func WSUpstreamH2C(result string) {
	_ws.h2cCache.getOrCreate(result, func() prometheus.Counter {
		return _ws.h2c.With(prometheus.Labels{"result": result})
	}).Inc()
}
