package metric

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var _ws wsMetric

type wsMetric struct {
	vec    *prometheus.CounterVec
	cache  *cache[string, prometheus.Counter]
	active prometheus.Gauge
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
