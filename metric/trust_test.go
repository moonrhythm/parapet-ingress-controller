package metric

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestTrustApplyEnum(t *testing.T) {
	for _, result := range []string{"applied", "rollback_rejected", "parse_rejected", "empty_rejected"} {
		before := testutil.ToFloat64(trustApplyHandles[result])
		TrustApply(result)
		if got := testutil.ToFloat64(trustApplyHandles[result]); got != before+1 {
			t.Errorf("TrustApply(%q): %v -> %v, want +1", result, before, got)
		}
	}
	// An unknown result is a no-op, never a panic.
	TrustApply("bogus")
}

func TestTrustSourceEnum(t *testing.T) {
	for _, src := range []TrustSrc{TrustSrcNone, TrustSrcCIDR, TrustSrcVerifiedChain} {
		before := testutil.ToFloat64(trustSourceCounters[src])
		TrustSource(src)
		if got := testutil.ToFloat64(trustSourceCounters[src]); got != before+1 {
			t.Errorf("TrustSource(%d): %v -> %v, want +1", src, before, got)
		}
	}
}

func TestTrustFetchFailed(t *testing.T) {
	before := testutil.ToFloat64(trustFetchFailed)
	TrustFetchFailed()
	if got := testutil.ToFloat64(trustFetchFailed); got != before+1 {
		t.Errorf("TrustFetchFailed: %v -> %v, want +1", before, got)
	}
}

// TrustBundleApplied keeps exactly one ca_id series across rotations and stamps the
// age clock so the GaugeFunc reports a fresh (small) age.
func TestTrustBundleAppliedOneSeries(t *testing.T) {
	TrustBundleApplied("ca-1", 5)
	TrustBundleApplied("ca-2", 6) // rotation
	if c := testutil.CollectAndCount(trustBundleGeneration); c != 1 {
		t.Errorf("want exactly 1 live generation series after rotation, got %d", c)
	}
	if v := testutil.ToFloat64(trustBundleGeneration.WithLabelValues("ca-2")); v != 6 {
		t.Errorf("generation = %v, want 6", v)
	}
	if lastApply.Load() == 0 {
		t.Error("lastApply must be stamped after an apply")
	}

	// An empty ca_id (a CP that served no fingerprint) must NOT mint a ca_id="" series
	// — symmetric with the edge helper — but still stamps the age clock.
	TrustBundleApplied("", 7)
	if c := testutil.CollectAndCount(trustBundleGeneration); c != 0 {
		t.Errorf("empty ca_id must leave no generation series, got %d", c)
	}
	if lastApply.Load() == 0 {
		t.Error("empty ca_id must still stamp the age clock")
	}
}

// Concurrent apply (single conceptual writer) vs scrape (many readers) must be
// race-free: run under `go test -race`.
func TestTrustBundleAppliedScrapeRace(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := uint64(100); i < 2100; i++ {
			TrustBundleApplied("ca-race", i)
		}
	}()
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				_ = testutil.CollectAndCount(trustBundleGeneration)
				_ = lastApply.Load()
			}
		}()
	}
	wg.Wait()
}
