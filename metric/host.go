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
	}, []string{"host", "kind"})
	_host.cache = newCache[hostKey, prometheus.Gauge](hostSizeHint)
	prom.Registry().MustRegister(_host.vec)
}

var _host host

type host struct {
	vec   *prometheus.GaugeVec
	cache *cache[hostKey, prometheus.Gauge]
}

// hostKey is the cache key for the per-(host,kind) gauge handle. A comparable
// struct avoids allocating a joined string key per request.
type hostKey struct {
	host string
	kind string
}

func (p *host) getM(host, kind string) prometheus.Gauge {
	return p.cache.getOrCreate(hostKey{host: host, kind: kind}, func() prometheus.Gauge {
		return p.vec.With(prometheus.Labels{
			"host": host,
			"kind": kind,
		})
	})
}

type promHostTracker struct {
	isKnownHost func(host string) bool
}

func (p promHostTracker) ServeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sanitize once so the Inc/Dec pair use the same (bounded) label.
		m := _host.getM(HostLabel(r.Host, p.isKnownHost), kindLabel(r.Header))
		m.Inc()
		defer m.Dec()

		h.ServeHTTP(w, r)
	})
}

// kindLabel classifies a request into one bounded connection-kind bucket for the
// host_active_requests gauge. The kinds are mutually exclusive, so one label is
// enough: an Upgrade request (websocket / h2c) is never also scored as SSE.
//
// The Upgrade header takes precedence and is checked first; it's client-
// controlled and arbitrary, so anything outside the known tokens collapses to
// "other" rather than reaching the gauge raw — otherwise a client could mint
// unbounded permanent series (and grow the handle cache) by flooding a known
// host with random Upgrade values, the same OOM class the host label guards
// against. With no Upgrade, a request whose Accept header asks for
// text/event-stream (what the browser EventSource API always sends) is "sse",
// splitting Server-Sent-Events streams out of the otherwise opaque plain bucket.
// Everything else is plain "http". The full set is bounded to
// {http, websocket, h2c, sse, other}.
func kindLabel(h http.Header) string {
	switch upgrade := strings.ToLower(strings.TrimSpace(header.Get(h, header.Upgrade))); upgrade {
	case "":
		// plain HTTP — may still be an SSE stream
	case "websocket", "h2c":
		return upgrade
	default:
		return "other"
	}

	if strings.Contains(strings.ToLower(header.Get(h, "Accept")), "text/event-stream") {
		return "sse"
	}
	return "http"
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
