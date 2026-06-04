package edge

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// setClientCertMetrics keeps exactly one ca_id series across re-mints, and an empty
// ca_id (too-short chain) sets only loaded without leaving a ca_id series.
func TestSetClientCertMetricsOneSeries(t *testing.T) {
	setClientCertMetrics("ca-old", 100)
	setClientCertMetrics("ca-new", 200) // re-mint onto a new CA set

	if c := testutil.CollectAndCount(edgeClientCertCAID); c != 1 {
		t.Errorf("ca_id: want 1 live series after re-mint, got %d", c)
	}
	if c := testutil.CollectAndCount(edgeClientCertNotAfter); c != 1 {
		t.Errorf("not_after: want 1 live series, got %d", c)
	}
	if v := testutil.ToFloat64(edgeClientCertLoaded.WithLabelValues("unknown")); v != 1 {
		t.Errorf("loaded = %v, want 1", v)
	}
	if v := testutil.ToFloat64(edgeClientCertNotAfter.WithLabelValues("ca-new", "unknown")); v != 200 {
		t.Errorf("not_after = %v, want 200", v)
	}

	// Empty ca_id: loaded stays 1, but no ca_id/not_after series.
	setClientCertMetrics("", 0)
	if c := testutil.CollectAndCount(edgeClientCertCAID); c != 0 {
		t.Errorf("empty ca_id must leave no series, got %d", c)
	}
}

func TestRemintEnum(t *testing.T) {
	for _, result := range []string{"ok", "keygen_fail", "csr_fail", "fetch_fail", "marshal_fail", "store_fail", "breaker_open"} {
		before := testutil.ToFloat64(edgeRemint.WithLabelValues(result, "reactive", "unknown"))
		remint(result, "reactive")
		if got := testutil.ToFloat64(edgeRemint.WithLabelValues(result, "reactive", "unknown")); got != before+1 {
			t.Errorf("remint(%q): %v -> %v, want +1", result, before, got)
		}
	}
}

func TestSetObservedTargetOneSeries(t *testing.T) {
	setObservedTarget("ca-a")
	setObservedTarget("ca-b") // rotation: one live series
	if c := testutil.CollectAndCount(edgeCPTargetCAID); c != 1 {
		t.Errorf("observed-target: want 1 live series, got %d", c)
	}
	if v := testutil.ToFloat64(edgeCPTargetCAID.WithLabelValues("ca-b", "unknown")); v != 1 {
		t.Errorf("observed-target ca-b = %v, want 1", v)
	}
	setObservedTarget("") // clears
	if c := testutil.CollectAndCount(edgeCPTargetCAID); c != 0 {
		t.Errorf("empty target must clear the series, got %d", c)
	}
}

// SetEdgeID stamps the edge_id label onto every metric, and edgeRefreshOK is an
// independent liveness heartbeat (bumps regardless of any ca_id change).
func TestEdgeIDStampingAndLiveness(t *testing.T) {
	old := edgeID
	edgeID = "edge-7"
	defer func() { edgeID = old }()

	setClientCertMetrics("ca-z", 123)
	if v := testutil.ToFloat64(edgeClientCertCAID.WithLabelValues("ca-z", "edge-7")); v != 1 {
		t.Error("ca_id series must carry the edge_id label")
	}
	if v := testutil.ToFloat64(edgeClientCertLoaded.WithLabelValues("edge-7")); v != 1 {
		t.Error("loaded must carry the edge_id label")
	}

	before := testutil.ToFloat64(edgeRefresh.WithLabelValues("edge-7"))
	edgeRefreshOK()
	if got := testutil.ToFloat64(edgeRefresh.WithLabelValues("edge-7")); got != before+1 {
		t.Errorf("edge_refresh_total: %v → %v, want +1", before, got)
	}
}
