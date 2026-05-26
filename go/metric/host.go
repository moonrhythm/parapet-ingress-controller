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

type promHostTracker struct {
	isKnownHost func(host string) bool
}

func (p promHostTracker) ServeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrade := upgradeLabel(strings.ToLower(strings.TrimSpace(header.Get(r.Header, header.Upgrade))))

		// Sanitize once so the Inc/Dec pair use the same (bounded) label.
		m := _host.getM(HostLabel(r.Host, p.isKnownHost), upgrade)
		m.Inc()
		defer m.Dec()

		h.ServeHTTP(w, r)
	})
}

// upgradeLabel collapses the client-controlled Upgrade header to a bounded label
// set for the host_active_requests gauge. The token is arbitrary, so labeling
// the gauge with it raw lets a client mint unbounded permanent series — and grow
// the handle cache — by sending random Upgrade values to a known host (the same
// OOM class the host label is sanitized against). Input is already lower-cased
// and trimmed; "" is the no-upgrade bucket, anything unrecognized is "other".
func upgradeLabel(upgrade string) string {
	switch upgrade {
	case "", "websocket", "h2c":
		return upgrade
	default:
		return "other"
	}
}

// HostActiveTracker returns middleware tracking in-flight requests per host.
// isKnownHost (may be nil) bounds the `host` label to the "other" sentinel for
// hosts the router doesn't serve.
func HostActiveTracker(isKnownHost func(host string) bool) parapet.Middleware {
	return promHostTracker{isKnownHost: isKnownHost}
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
