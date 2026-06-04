package edgecp

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSetRegistryMetrics(t *testing.T) {
	SetRegistryMetrics(map[string]Entry{
		"tok-a": {ID: "edge-a", Domains: []string{"a.com"}},
		"tok-b": {ID: "edge-b", Domains: []string{"b.com"}, Disabled: true},
		"tok-c": {Domains: []string{"c.com"}}, // no id (cert-only token) → not an edge
	})
	if v := testutil.ToFloat64(registryTotal.WithLabelValues("edge-a")); v != 1 {
		t.Errorf("enabled edge: registry_total = %v, want 1", v)
	}
	if v := testutil.ToFloat64(registryTotal.WithLabelValues("edge-b")); v != 0 {
		t.Errorf("disabled edge: registry_total = %v, want 0", v)
	}
	// Only the two id-bearing edges are reported.
	if c := testutil.CollectAndCount(registryTotal); c != 2 {
		t.Errorf("registry_total series = %d, want 2 (cert-only token excluded)", c)
	}
}

// authz_generation must be replica-identical (same registry → same value) and change
// when the registry changes (the blacklist-barrier signal).
func TestAuthzGenerationFingerprint(t *testing.T) {
	a := registryFingerprint([]string{"edge-a:0", "edge-b:1"})
	aReordered := registryFingerprint([]string{"edge-b:1", "edge-a:0"}) // order-independent
	if a != aReordered {
		t.Error("fingerprint must be order-independent (replica-identical)")
	}
	blacklisted := registryFingerprint([]string{"edge-a:0", "edge-b:0"}) // edge-b enabled
	if a == blacklisted {
		t.Error("fingerprint must change when an edge's disabled flag changes")
	}
	if a < 0 || a >= (1<<48) {
		t.Errorf("fingerprint %v must be a non-negative float < 2^48 (float64-exact)", a)
	}
}
