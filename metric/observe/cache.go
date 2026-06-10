package observe

import (
	"net/http"
	"sync"

	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

// _respCache holds the response-cache outcome metrics. Unlike the package's
// other metrics it registers lazily (first CacheResult call), NOT in init():
// the fill histogram is labelless, so registering it exports a zero series
// immediately — and the controller binary imports this package for the WAF and
// ratelimit observers but has no response cache, so it must not grow cache
// series it can never move.
var _respCache struct {
	once  sync.Once
	total map[cache.Result]prometheus.Counter
	fill  prometheus.Histogram
}

// CacheResult returns a cache.ResultFunc for cache.Options.OnResult recording:
//
//	parapet_cache_total{result}             counter (HIT|MISS|STALE|STALE_ERROR|BYPASS)
//	parapet_cache_fill_duration_seconds     histogram of origin-fill latency
//	    (FillDuration is non-zero only when the origin was contacted on the
//	     serving path — a MISS fill or a stale-if-error revalidation — so hits
//	     don't dilute it)
//
// These are parapet's prom.Cache metrics WITHOUT the host label: the edge
// serves any Host the client sends (serve-all), so r.Host is attacker-
// controlled and would mint unbounded series. The result label is cache's
// closed five-value set; handles are resolved once, so the per-request hook is
// alloc- and lookup-free. An unknown Result is dropped rather than labeled.
func CacheResult() cache.ResultFunc {
	_respCache.once.Do(func() {
		vec := prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: prom.Namespace,
			Name:      "cache_total",
		}, []string{"result"})
		_respCache.total = make(map[cache.Result]prometheus.Counter)
		for _, res := range []cache.Result{
			cache.ResultHit, cache.ResultMiss, cache.ResultStale,
			cache.ResultStaleError, cache.ResultBypass,
		} {
			_respCache.total[res] = vec.With(prometheus.Labels{"result": string(res)})
		}
		_respCache.fill = prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: prom.Namespace,
			Name:      "cache_fill_duration_seconds",
			Buckets:   prometheus.DefBuckets,
		})
		prom.Registry().MustRegister(vec, _respCache.fill)
	})
	return func(_ *http.Request, info cache.ResultInfo) {
		if c, ok := _respCache.total[info.Result]; ok {
			c.Inc()
		}
		if info.FillDuration > 0 {
			_respCache.fill.Observe(info.FillDuration.Seconds())
		}
	}
}
