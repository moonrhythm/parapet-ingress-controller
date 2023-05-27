package metric

import (
	"net/http"
	"strings"
	"sync"

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
	_hostRatelimit.m = make(map[string]prometheus.Counter, hostSizeHint)
	prom.Registry().MustRegister(_hostRatelimit.vec)

	_host.vec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "host_active_requests",
	}, []string{"host", "upgrade"})
	_host.m = make(map[string]prometheus.Gauge, hostSizeHint)
	prom.Registry().MustRegister(_host.vec)
}

var _host host

type host struct {
	vec *prometheus.GaugeVec

	mu sync.RWMutex
	m  map[string]prometheus.Gauge // host/upgrade
}

func (p *host) getM(host, upgrade string) prometheus.Gauge {
	key := strings.Join([]string{
		host,
		upgrade,
	}, "/")

	p.mu.RLock()
	m := p.m[key]
	p.mu.RUnlock()

	if m == nil {
		p.mu.Lock()
		if p.m[key] == nil {
			p.m[key] = p.vec.With(prometheus.Labels{
				"host":    host,
				"upgrade": upgrade,
			})
		}
		m = p.m[key]
		p.mu.Unlock()
	}

	return m
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
	vec *prometheus.CounterVec

	mu sync.RWMutex
	m  map[string]prometheus.Counter // host
}

func (p *promHostRatelimit) Inc(host string) {
	p.mu.RLock()
	m := p.m[host]
	p.mu.RUnlock()

	if m == nil {
		p.mu.Lock()
		if p.m[host] == nil {
			p.m[host] = p.vec.With(prometheus.Labels{
				"host": host,
			})
		}
		m = p.m[host]
		p.mu.Unlock()
	}

	m.Inc()
}

// HostRatelimitRequest increments the host ratelimit counter
func HostRatelimitRequest(host string) {
	_hostRatelimit.Inc(host)
}
