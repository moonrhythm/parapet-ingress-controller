package metric

import (
	"net/http"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var _hostRatelimit hostRatelimit

type hostRatelimit struct {
	requests *prometheus.CounterVec
	active   *prometheus.GaugeVec
	upgrade  *prometheus.GaugeVec
}

func init() {
	_hostRatelimit.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "host_ratelimit_requests",
	}, []string{"host"})
	_hostRatelimit.active = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "host_ratelimit_active_requests",
	}, []string{"host"})
	_hostRatelimit.upgrade = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "host_ratelimit_active_upgrades",
	}, []string{"host"})
	prom.Registry().MustRegister(_hostRatelimit.requests)
	prom.Registry().MustRegister(_hostRatelimit.active)
	prom.Registry().MustRegister(_hostRatelimit.upgrade)
}

// HostRatelimitRequest increments the host ratelimit counter
func HostRatelimitRequest(host string) {
	l := prometheus.Labels{
		"host": host,
	}

	counter, err := _hostRatelimit.requests.GetMetricWith(l)
	if err != nil {
		return
	}
	counter.Inc()
}

type promHostRatelimitTracker struct {
	vec     *prometheus.GaugeVec
	upgrade bool
}

func (p *promHostRatelimitTracker) ServeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isUpgrade := r.Header.Get("Upgrade") != ""
		if isUpgrade != p.upgrade {
			h.ServeHTTP(w, r)
			return
		}

		host := r.Host
		p.incr(host)
		defer p.decr(host)

		h.ServeHTTP(w, r)
	})
}

func (p *promHostRatelimitTracker) incr(host string) {
	l := prometheus.Labels{
		"host": host,
	}

	gauge, err := p.vec.GetMetricWith(l)
	if err != nil {
		return
	}
	gauge.Inc()
}

func (p *promHostRatelimitTracker) decr(host string) {
	l := prometheus.Labels{
		"host": host,
	}

	gauge, err := p.vec.GetMetricWith(l)
	if err != nil {
		return
	}
	gauge.Dec()
}

func HostRateLimitActiveTracker() parapet.Middleware {
	return &promHostRatelimitTracker{_hostRatelimit.active, false}
}

func HostRateLimitUpgradeTracker() parapet.Middleware {
	return &promHostRatelimitTracker{_hostRatelimit.upgrade, true}
}
