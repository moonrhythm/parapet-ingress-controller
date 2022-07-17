package metric

import (
	"net/http"
	"strings"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var _host host

type host struct {
	limits *prometheus.CounterVec
	active *prometheus.GaugeVec
}

func init() {
	_host.limits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "host_ratelimit_requests",
	}, []string{"host"})
	_host.active = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "host_active_requests",
	}, []string{"host", "upgrade"})
	prom.Registry().MustRegister(_host.limits)
	prom.Registry().MustRegister(_host.active)
}

// HostRatelimitRequest increments the host ratelimit counter
func HostRatelimitRequest(host string) {
	l := prometheus.Labels{
		"host": host,
	}

	counter, err := _host.limits.GetMetricWith(l)
	if err != nil {
		return
	}
	counter.Inc()
}

type promHostTracker struct{}

func (p promHostTracker) ServeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := prometheus.Labels{
			"host":    r.Host,
			"upgrade": strings.ToLower(strings.TrimSpace(r.Header.Get("Upgrade"))),
		}
		if g, _ := _host.active.GetMetricWith(l); g != nil {
			g.Inc()
			defer g.Dec()
		}

		h.ServeHTTP(w, r)
	})
}

func HostActiveTracker() parapet.Middleware {
	return promHostTracker{}
}
