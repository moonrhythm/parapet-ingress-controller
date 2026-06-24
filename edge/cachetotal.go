package edge

// cachetotal.go — host-bounded parapet_cache_total counter for the edge.
//
// WHY THIS EXISTS
//
// parapet's prom.Cache (and the shared metric/observe.CacheResult helper) emit
// parapet_cache_total WITHOUT a host label, because the serve-all edge accepts
// any client Host and an unbounded host label would mint unbounded series. That
// makes the counter a single global-per-edge total — fine for a fleet hit-ratio
// alert, but it cannot attribute cache outcomes back to a project/host the way
// the per-project usage pipeline needs.
//
// parapet_requests and parapet_cache_egress_bytes face the exact same serve-all
// hazard and solve it the same way: the edge registers its own copy of the
// family with a host label bounded by the knownHost oracle (unknown hosts
// collapse to "other"). CacheTotal is that treatment for the cache-outcome
// counter — it replaces observe.CacheResult on the edge, recording the same
// parapet_cache_fill_duration_seconds histogram so nothing is lost.
//
// LABEL CARDINALITY INVARIANTS
//
//   - host: bounded by knownHost (same oracle as parapet_requests /
//     parapet_cache_egress_bytes). Unknown hosts collapse to "other".
//   - result: cache's closed five-value set (HIT/MISS/STALE/STALE_ERROR/BYPASS).
//   - edge_id: single cardinality per process — the global edgeID var.

import (
	"net/http"
	"sync"

	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	cacheTotalOnce sync.Once
	cacheTotalVec  *prometheus.CounterVec
	cacheFillHist  prometheus.Histogram
)

func cacheTotalRegister() {
	cacheTotalOnce.Do(func() {
		cacheTotalVec = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: prom.Namespace,
			Name:      "cache_total",
			Help:      "Edge response-cache outcomes, by result (HIT/MISS/STALE/STALE_ERROR/BYPASS) and host. Hit ratio = HIT / all. Host is bounded by the knownHost oracle (\"other\" when not served), like parapet_requests.",
		}, []string{"host", "result", "edge_id"})
		cacheFillHist = prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: prom.Namespace,
			Name:      "cache_fill_duration_seconds",
			Help:      "Origin-fill latency, observed only when the origin was contacted on the serving path (a MISS fill or a stale-if-error revalidation).",
			Buckets:   prometheus.DefBuckets,
		})
		prom.Registry().MustRegister(cacheTotalVec, cacheFillHist)
	})
}

// CacheTotal returns a cache.ResultFunc for cache.Options.OnResult that records
// the host-bounded parapet_cache_total{host,result,edge_id} counter and the
// parapet_cache_fill_duration_seconds histogram. It is the edge's host-bounded
// replacement for metric/observe.CacheResult (which is host-less); mount one or
// the other, never both — they register the same metric family names.
//
// knownHost (may be nil — then the host passes through, as in tests) bounds the
// host label: a host it reports false for collapses to the "other" sentinel.
func CacheTotal(knownHost func(host string) bool) cache.ResultFunc {
	cacheTotalRegister()
	return func(r *http.Request, info cache.ResultInfo) {
		cacheTotalVec.WithLabelValues(
			hostLabel(r.Host, knownHost),
			string(info.Result),
			edgeID,
		).Inc()
		if info.FillDuration > 0 {
			cacheFillHist.Observe(info.FillDuration.Seconds())
		}
	}
}
