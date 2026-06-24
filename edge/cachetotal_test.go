package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// cacheTotalCount reads the current counter value for the given host+result.
// CacheTotal() registers the vec, so call it first.
func cacheTotalCount(host, result string) float64 {
	return testutil.ToFloat64(cacheTotalVec.WithLabelValues(host, result, edgeID))
}

// recordCacheResult drives one cache outcome through the CacheTotal ResultFunc.
func recordCacheResult(host string, result cache.Result, fill time.Duration) {
	fn := CacheTotal(knownCacheHost)
	r := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	r.Host = host
	fn(r, cache.ResultInfo{Result: result, FillDuration: fill})
}

func TestCacheTotalCountsEveryResult(t *testing.T) {
	CacheTotal(knownCacheHost) // ensure registered

	// All five closed-set results increment their own (host, result) series — in
	// particular BYPASS, which cache egress bytes deliberately drops.
	for _, res := range []cache.Result{
		cache.ResultHit, cache.ResultMiss, cache.ResultStale,
		cache.ResultStaleError, cache.ResultBypass,
	} {
		before := cacheTotalCount("known.example.com", string(res))
		recordCacheResult("known.example.com", res, 0)
		after := cacheTotalCount("known.example.com", string(res))
		if got := after - before; got != 1 {
			t.Errorf("result %s: got %.0f, want 1", res, got)
		}
	}
}

func TestCacheTotalUnknownHostCollapsesToOther(t *testing.T) {
	CacheTotal(knownCacheHost)

	before := cacheTotalCount("other", "HIT")
	recordCacheResult("evil.example.net", cache.ResultHit, 0) // unknown host → "other"
	after := cacheTotalCount("other", "HIT")
	if got := after - before; got != 1 {
		t.Errorf("unknown host: got %.0f under \"other\", want 1", got)
	}
}

func TestCacheTotalAccumulates(t *testing.T) {
	CacheTotal(knownCacheHost)

	before := cacheTotalCount("known.example.com", "HIT")
	for i := 0; i < 5; i++ {
		recordCacheResult("known.example.com", cache.ResultHit, 0)
	}
	after := cacheTotalCount("known.example.com", "HIT")
	if got := after - before; got != 5 {
		t.Errorf("accumulate: got %.0f, want 5", got)
	}
}

func TestCacheTotalFillDurationObserved(t *testing.T) {
	CacheTotal(knownCacheHost)

	// A MISS with a non-zero fill duration records into the histogram (and must
	// not panic); a hit with zero fill does not. We assert the histogram's total
	// sample count rises by exactly one across a fill + a no-fill outcome.
	before := histogramSampleCount(t)
	recordCacheResult("known.example.com", cache.ResultMiss, 5*time.Millisecond)
	recordCacheResult("known.example.com", cache.ResultHit, 0) // zero fill → not observed
	after := histogramSampleCount(t)
	if got := after - before; got != 1 {
		t.Errorf("fill histogram samples: got +%d, want +1", got)
	}
}

// histogramSampleCount returns the cache-fill histogram's total observation count.
func histogramSampleCount(t *testing.T) uint64 {
	t.Helper()
	m := &dto.Metric{}
	if err := cacheFillHist.Write(m); err != nil {
		t.Fatalf("write histogram: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}
