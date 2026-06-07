package metric

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/moonrhythm/parapet-ingress-controller/state"
)

const requestSizeHint = 1000

// Requests returns middleware that collect request information. isKnownHost (may
// be nil) bounds the `host` label: a host the router doesn't serve collapses to
// the "other" sentinel so a random-Host flood can't grow series cardinality.
func Requests(isKnownHost func(host string) bool) parapet.Middleware {
	_promRequests.isKnownHost = isKnownHost
	return &_promRequests
}

var _promRequests promRequests

type promRequests struct {
	vec       *prometheus.CounterVec
	durations *prometheus.HistogramVec

	cache *cache[requestKey, *requestMetric]

	isKnownHost func(host string) bool
}

// requestKey is the cache key for the per-label-set metric handles. Using a
// comparable struct instead of a joined string avoids allocating a key on
// every request and removes any separator-collision risk.
type requestKey struct {
	host        string
	namespace   string
	ingress     string
	serviceName string
	serviceType string
	method      string
	status      string
}

// requestMetric bundles the counter and duration observer for one label set so
// the hot path resolves both with a single map lookup.
type requestMetric struct {
	counter  prometheus.Counter
	observer prometheus.Observer
}

func init() {
	_promRequests.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "requests",
	}, []string{"host", "status", "method", "ingress_name", "ingress_namespace", "service_type", "service_name"})
	_promRequests.durations = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: prom.Namespace,
		Name:      "service_duration_seconds",
	}, []string{"service_type", "service_namespace", "service_name"})
	_promRequests.cache = newCache[requestKey, *requestMetric](requestSizeHint)

	prom.Registry().MustRegister(_promRequests.vec, _promRequests.durations)
}

// methodLabel collapses the client-controlled request method to a bounded label
// set for the `requests` metric. net/http admits any RFC7230 token as a method
// (it only rejects invalid token characters), so labeling the counter — and
// keying the handle cache — with the raw method lets a client mint unbounded
// permanent series, and grow the cache, by sending random method tokens to a
// host the router serves (the same OOM class host/upgrade are sanitized
// against). Only the registered HTTP methods pass through; anything else
// collapses to "other".
func methodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect,
		http.MethodOptions, http.MethodTrace:
		return method
	default:
		return "other"
	}
}

// statusLabel bounds the response status label for the `requests` metric. An
// upstream can write any int via WriteHeader, so labeling the counter — and keying
// the handle cache — with the raw code lets a buggy/hostile backend mint unbounded
// permanent series (the same OOM class methodLabel guards against). Valid HTTP
// codes (100–599) pass through; anything else collapses to "other".
func statusLabel(status int) string {
	if status >= 100 && status <= 599 {
		return strconv.Itoa(status)
	}
	return "other"
}

func (p *promRequests) Inc(r *http.Request, status int, start time.Time) {
	duration := time.Since(start)

	ctx := r.Context()
	s := state.Get(ctx)

	host := HostLabel(r.Host, p.isKnownHost)
	method := methodLabel(r.Method)
	statusStr := statusLabel(status)

	// Edge rejection: a tracked rejection status where the request never reached
	// a backend (makeHandler sets serviceTarget only when it proxies). Counted in
	// the host-less rejected_requests metric, so an abusive flood can't grow its
	// cardinality the way the host-labeled `requests` metric otherwise would.
	if reason := edgeRejectReason(s["serviceTarget"] != "", status); reason != "" {
		RejectedRequest(reason)
	}

	key := requestKey{
		host:        host,
		namespace:   s["namespace"],
		ingress:     s["ingress"],
		serviceName: s["serviceName"],
		serviceType: s["serviceType"],
		method:      method,
		status:      statusStr,
	}

	rm := p.cache.getOrCreate(key, func() *requestMetric {
		return &requestMetric{
			counter: p.vec.With(prometheus.Labels{
				"host":              host,
				"method":            method,
				"ingress_name":      s["ingress"],
				"ingress_namespace": s["namespace"],
				"service_type":      s["serviceType"],
				"service_name":      s["serviceName"],
				"status":            statusStr,
			}),
			observer: p.durations.With(prometheus.Labels{
				"service_type":      s["serviceType"],
				"service_name":      s["serviceName"],
				"service_namespace": s["namespace"],
			}),
		}
	})

	rm.counter.Inc()
	rm.observer.Observe(duration.Seconds())
}

func (p *promRequests) ServeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		nw := requestTrackRW{
			ResponseWriter: w,
		}
		defer func() { p.Inc(r, nw.status, start) }()

		h.ServeHTTP(&nw, r)
	})
}

type requestTrackRW struct {
	http.ResponseWriter

	wroteHeader bool
	status      int
}

func (w *requestTrackRW) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *requestTrackRW) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (w *requestTrackRW) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Push implements Pusher interface
func (w *requestTrackRW) Push(target string, opts *http.PushOptions) error {
	if w, ok := w.ResponseWriter.(http.Pusher); ok {
		return w.Push(target, opts)
	}
	return http.ErrNotSupported
}

// Flush implements Flusher interface
func (w *requestTrackRW) Flush() {
	if w, ok := w.ResponseWriter.(http.Flusher); ok {
		w.Flush()
	}
}

// Hijack implements Hijacker interface
func (w *requestTrackRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w, ok := w.ResponseWriter.(http.Hijacker); ok {
		return w.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}
