package metric

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/moonrhythm/parapet-ingress-controller/state"
)

const requestSizeHint = 1000

// Requests returns middleware that collect request information
func Requests() parapet.Middleware {
	return &_promRequests
}

var _promRequests promRequests

type promRequests struct {
	vec *prometheus.CounterVec

	mu sync.RWMutex
	m  map[string]prometheus.Counter // host/namespace/ingress/service/type/method/status
}

func init() {
	_promRequests.vec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "requests",
	}, []string{"host", "status", "method", "ingress_name", "ingress_namespace", "service_type", "service_name"})
	_promRequests.m = make(map[string]prometheus.Counter, requestSizeHint)

	prom.Registry().MustRegister(_promRequests.vec)
}

func (p *promRequests) Inc(r *http.Request, status int) {
	ctx := r.Context()
	s := state.Get(ctx)

	key := strings.Join([]string{
		r.Host,
		s["namespace"],
		s["ingress"],
		s["serviceName"],
		s["serviceType"],
		r.Method,
		strconv.Itoa(status),
	}, "/")

	p.mu.RLock()
	m := p.m[key]
	p.mu.RUnlock()

	if m == nil {
		p.mu.Lock()
		if p.m[key] == nil {
			p.m[key] = p.vec.With(prometheus.Labels{
				"host":              r.Host,
				"method":            r.Method,
				"ingress_name":      s["ingress"],
				"ingress_namespace": s["namespace"],
				"service_type":      s["serviceType"],
				"service_name":      s["serviceName"],
				"status":            strconv.Itoa(status),
			})
		}
		m = p.m[key]
		p.mu.Unlock()
	}

	m.Inc()
}

func (p *promRequests) ServeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nw := requestTrackRW{
			ResponseWriter: w,
		}
		defer func() { p.Inc(r, nw.status) }()

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
