package edgecp

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// setSignerMetrics must keep EXACTLY ONE live series per ca_id vec across rotations
// (Reset()-then-Set) — the only guard against ca_id-label cardinality growth in a
// long-running process — and reflect the latest signer's values.
func TestSetSignerMetricsOneSeriesPerVec(t *testing.T) {
	setSignerMetrics("ca-old", 1, 2)
	setSignerMetrics("ca-new", 2, 1) // rotate: a new ca_id must not accumulate a series

	for name, c := range map[string]int{
		"signer_fingerprint": testutil.CollectAndCount(signerFingerprint),
		"signer_generation":  testutil.CollectAndCount(signerGeneration),
		"bundle_certs":       testutil.CollectAndCount(signerBundleCerts),
		"target_ca_id":       testutil.CollectAndCount(targetCAID),
	} {
		if c != 1 {
			t.Errorf("%s: want exactly 1 live series after a rotation, got %d", name, c)
		}
	}

	if v := testutil.ToFloat64(signerLoaded); v != 1 {
		t.Errorf("signer_loaded = %v, want 1", v)
	}
	if v := testutil.ToFloat64(signerGeneration.WithLabelValues("ca-new")); v != 2 {
		t.Errorf("generation = %v, want 2", v)
	}
	if v := testutil.ToFloat64(signerBundleCerts.WithLabelValues("ca-new")); v != 1 {
		t.Errorf("bundle_certs = %v, want 1", v)
	}
	if v := testutil.ToFloat64(signerFingerprint.WithLabelValues("ca-new")); v != 1 {
		t.Errorf("fingerprint = %v, want 1", v)
	}
}
