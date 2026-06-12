package edge

// cacheegress.go — parapet_cache_egress_bytes counter.
//
// WHY THIS EXISTS
//
// The edge response cache serves HITs entirely from its local store — the
// origin (parapet core) is never contacted. That makes HIT traffic invisible
// to every existing byte counter:
//   - parapet_backend_network_read_bytes only increments on origin reads
//     (MISSes/STALEs that require a fill), so HIT bytes never appear there.
//   - Pod egress metrics are per-pod kernel counters: an edge HIT never
//     reaches the pod, so those bytes are missing there too.
//
// parapet_cache_egress_bytes{host,result,edge_id} fills that gap. It counts
// every response-body byte written to the client, partitioned by cache result,
// giving billing the cache egress volume for HIT/STALE/MISS paths alike.
//
// LABEL CARDINALITY INVARIANTS
//
//   - host: bounded by knownHost (same oracle as parapet_requests). Unknown
//     hosts collapse to "other" so a Host-flood can't create unbounded series.
//   - result: bounded explicitly — only HIT, STALE, MISS from the X-Cache
//     header pass through; any other value collapses to "other" (defense in
//     depth; the header is set by our own cache.go, not by the client).
//     Empty X-Cache (cache bypass, hijacked upgrade, etc.) records NOTHING,
//     keeping series from accumulating for uncached traffic.
//   - edge_id: single cardinality per process — the global edgeID var.

import (
	"bufio"
	"net"
	"net/http"
	"sync"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	cacheEgressOnce sync.Once
	cacheEgressVec  *prometheus.CounterVec
)

func cacheEgressRegister() {
	cacheEgressOnce.Do(func() {
		cacheEgressVec = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: prom.Namespace,
			Name:      "cache_egress_bytes",
			Help:      "Response body bytes served by the edge, by cache result (HIT/STALE/MISS) and host. Only present when the response cache is enabled. HIT bytes are the billing source for cache egress because they are invisible to origin-side byte counters.",
		}, []string{"host", "result", "edge_id"})
		prom.Registry().MustRegister(cacheEgressVec)
	})
}

// CacheEgress returns middleware counting response-body bytes served by the
// edge as parapet_cache_egress_bytes{host,result,edge_id}. Mount it
// immediately BEFORE the response-cache middleware so it wraps every response
// the cache emits (hits, stales, and fills alike).
//
// Only responses carrying an X-Cache header (set by parapet's cache on every
// managed response) are counted. Responses without X-Cache — bypass, hijacked
// WebSocket upgrades, etc. — produce no series, keeping cardinality clean.
//
// knownHost bounds the host label; pass edgeHosts.IsKnownHost (same func
// as Requests). nil is accepted and leaves the host label unfiltered (useful
// in tests).
func CacheEgress(knownHost func(host string) bool) parapet.Middleware {
	cacheEgressRegister()
	return &cacheEgressMiddleware{knownHost: knownHost}
}

type cacheEgressMiddleware struct {
	knownHost func(host string) bool
}

func (p *cacheEgressMiddleware) ServeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nw := &cacheEgressRW{ResponseWriter: w}
		h.ServeHTTP(nw, r)
		// Read X-Cache after the inner handler returns (cache has written it).
		result := cacheResultLabel(nw.Header().Get("X-Cache"))
		if result == "" {
			// No X-Cache: not cache-managed (bypass, upgrade, etc.) — skip.
			return
		}
		if nw.bytes == 0 {
			// Zero-byte body but X-Cache present (e.g. HEAD, 304): still
			// record so hit-ratio-by-bytes queries see the series.
		}
		cacheEgressVec.WithLabelValues(
			hostLabel(r.Host, p.knownHost),
			result,
			edgeID,
		).Add(float64(nw.bytes))
	})
}

// cacheResultLabel maps the X-Cache header value to a bounded label.
// Returns "" for an absent/empty header (caller skips recording).
func cacheResultLabel(v string) string {
	switch v {
	case "":
		return ""
	case "HIT", "STALE", "MISS":
		return v
	default:
		// Unexpected value (defense in depth — our cache.go is the only
		// writer of X-Cache, but bound the label unconditionally).
		return "other"
	}
}

// cacheEgressRW wraps ResponseWriter to count bytes passed through Write
// while preserving the optional interfaces the middleware chain relies on:
// Flush (SSE/chunked), Hijack (WebSocket/upgrade), Push (HTTP/2), Unwrap.
type cacheEgressRW struct {
	http.ResponseWriter
	bytes int64
}

func (w *cacheEgressRW) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (w *cacheEgressRW) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Flush implements http.Flusher.
func (w *cacheEgressRW) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker.
func (w *cacheEgressRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Push implements http.Pusher.
func (w *cacheEgressRW) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
