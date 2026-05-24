package metric

import (
	"net/http"
	"strings"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/header"
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

const hostSizeHint = 100

func init() {
	_hostRatelimit.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "host_ratelimit_requests",
	}, []string{"host"})
	_hostRatelimit.cache = newCache[string, prometheus.Counter](hostSizeHint)
	prom.Registry().MustRegister(_hostRatelimit.vec)

	_host.vec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "host_active_requests",
	}, []string{"host", "upgrade"})
	_host.cache = newCache[hostKey, prometheus.Gauge](hostSizeHint)
	prom.Registry().MustRegister(_host.vec)
}

var _host host

type host struct {
	vec   *prometheus.GaugeVec
	cache *cache[hostKey, prometheus.Gauge]
}

// hostKey is the cache key for the per-(host,upgrade) gauge handle. A
// comparable struct avoids allocating a joined string key per request.
type hostKey struct {
	host    string
	upgrade string
}

func (p *host) getM(host, upgrade string) prometheus.Gauge {
	return p.cache.getOrCreate(hostKey{host: host, upgrade: upgrade}, func() prometheus.Gauge {
		return p.vec.With(prometheus.Labels{
			"host":    host,
			"upgrade": upgrade,
		})
	})
}

type promHostTracker struct{}

func (p promHostTracker) ServeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrade := strings.ToLower(strings.TrimSpace(header.Get(r.Header, header.Upgrade)))

		m := _host.getM(r.Host, upgrade)
		m.Inc()
		defer m.Dec()

		h.ServeHTTP(w, r)
	})
}

func HostActiveTracker() parapet.Middleware {
	return promHostTracker{}
}

var _hostRatelimit promHostRatelimit

type promHostRatelimit struct {
	vec   *prometheus.CounterVec
	cache *cache[string, prometheus.Counter]
}

func (p *promHostRatelimit) Inc(host string) {
	p.cache.getOrCreate(host, func() prometheus.Counter {
		return p.vec.With(prometheus.Labels{
			"host": host,
		})
	}).Inc()
}

// HostRatelimitRequest increments the host ratelimit counter
func HostRatelimitRequest(host string) {
	_hostRatelimit.Inc(host)
}
