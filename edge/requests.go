package edge

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

// parapet_requests is the per-request counter the in-cluster controller already
// exports (metric.Requests). The edge can't import that package — it would
// materialize the controller's core-trust alerting series (see metric/observe
// and import_boundary_test.go) — and parapet's own prom.Requests carries an
// UNBOUNDED host label, which a serve-all edge (any client Host) must not export.
// So the edge registers the SAME family name here with a host label of its own
// bounding. It merges into the controller's parapet_requests family at the
// control plane (edgecp.mergeFamilies, by family name + matching counter type);
// edge series are told apart by the edge_id/edge_instance labels the CP stamps
// at ingest, and by carrying neither the ingress_* nor service_* labels.
//
// All three input-derived labels are bounded so request input can't grow series
// cardinality (the OOM class the controller's metric.Requests guards the same
// way): host collapses to "other" for any host the edge doesn't serve, method to
// "other" outside the registered HTTP methods (any RFC7230 token is a valid
// method), and status to "other" outside 100–599 (an upstream can write any code).
var (
	requestsOnce sync.Once
	requestsVec  *prometheus.CounterVec
)

func requestsRegister() {
	requestsOnce.Do(func() {
		requestsVec = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: prom.Namespace,
			Name:      "requests",
			Help:      "Requests served by the edge, by host (collapsed to \"other\" when not served), status, method.",
		}, []string{"host", "status", "method", "edge_id"})
		prom.Registry().MustRegister(requestsVec)
	})
}

// Requests returns middleware counting every served request as
// parapet_requests{host,status,method,edge_id}. knownHost (may be nil — then the
// host passes through, as in tests) bounds the host label: a host it reports
// false for collapses to the "other" sentinel. Mount it outermost so the counted
// status is the one the client sees — WAF blocks, rate-limit rejects, cache hits,
// and proxied responses alike.
func Requests(knownHost func(host string) bool) parapet.Middleware {
	requestsRegister()
	return &requestsMiddleware{knownHost: knownHost}
}

type requestsMiddleware struct {
	knownHost func(host string) bool
}

func (p *requestsMiddleware) ServeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nw := requestTrackRW{ResponseWriter: w}
		defer func() {
			requestsVec.WithLabelValues(
				hostLabel(r.Host, p.knownHost),
				statusLabel(nw.status),
				methodLabel(r.Method),
				edgeID,
			).Inc()
		}()
		h.ServeHTTP(&nw, r)
	})
}

// unknownHostLabel substitutes for a host the edge doesn't serve, so a flood of
// random Host headers can't create unbounded host-labeled series. Matches
// metric.HostLabel's "other" so edge and controller series share one bucket.
const unknownHostLabel = "other"

func hostLabel(host string, knownHost func(string) bool) string {
	if knownHost == nil || knownHost(host) {
		return host
	}
	return unknownHostLabel
}

// methodLabel collapses the client-controlled method to a bounded set; only the
// registered HTTP methods pass through, anything else becomes "other".
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

// statusLabel bounds the response status: valid HTTP codes (100–599) pass
// through, anything else (including 0 — a hijacked/empty response) is "other".
func statusLabel(status int) string {
	if status >= 100 && status <= 599 {
		return strconv.Itoa(status)
	}
	return "other"
}

// requestTrackRW captures the response status while preserving the optional
// ResponseWriter interfaces the chain relies on (Flush for SSE, Hijack for
// websockets/upgrades, Push), mirroring parapet's prom.Requests writer.
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

// Push implements the http.Pusher interface.
func (w *requestTrackRW) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// Flush implements the http.Flusher interface.
func (w *requestTrackRW) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements the http.Hijacker interface.
func (w *requestTrackRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}
