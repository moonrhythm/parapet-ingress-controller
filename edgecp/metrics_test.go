package edgecp

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// setSignerMetrics must keep EXACTLY ONE live series per ca_id vec across rotations
// (Reset()-then-Set) — the only guard against ca_id-label cardinality growth in a
// long-running process — and reflect the latest signer's values.
func TestSetSignerMetricsOneSeriesPerVec(t *testing.T) {
	setSignerMetrics("ca-old", "fp-old", 1, 2)
	setSignerMetrics("ca-new", "fp-new", 2, 1) // rotate: a new ca_id must not accumulate a series

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
	// The active-signer fp vec is also one-series-per-rotation, keyed (ca_id, sigfp).
	if c := testutil.CollectAndCount(activeSignerFP); c != 1 {
		t.Errorf("active_signer_fp: want 1 live series, got %d", c)
	}
	if v := testutil.ToFloat64(activeSignerFP.WithLabelValues("ca-new", "fp-new")); v != 1 {
		t.Errorf("active_signer_fp{ca-new,fp-new} = %v, want 1", v)
	}
}

// The CP-authoritative issuance ledger is the interlock's proof a revoked id never minted
// under NEW: it counts per (edge_id, active signer fp), so the same id under OLD vs NEW are
// distinct series (a revoke asserts the NEW one is zero).
func TestRecordIssuanceLedger(t *testing.T) {
	issuedUnderSigner.Reset()
	recordIssuance("edge-a", "fp-new")
	recordIssuance("edge-a", "fp-new")
	recordIssuance("edge-a", "fp-old") // same edge, OLD signer — a separate series
	recordIssuance("edge-b", "fp-new")

	if v := testutil.ToFloat64(issuedUnderSigner.WithLabelValues("edge-a", "fp-new")); v != 2 {
		t.Errorf("issued{edge-a,fp-new} = %v, want 2", v)
	}
	if v := testutil.ToFloat64(issuedUnderSigner.WithLabelValues("edge-a", "fp-old")); v != 1 {
		t.Errorf("issued{edge-a,fp-old} = %v, want 1 (OLD must not fold into NEW)", v)
	}
	if v := testutil.ToFloat64(issuedUnderSigner.WithLabelValues("edge-b", "fp-new")); v != 1 {
		t.Errorf("issued{edge-b,fp-new} = %v, want 1", v)
	}
}

// A blacklisted token flags edge_token_disabled_without_rotation (the bare-blacklist
// reminder); enabled tokens leave no series, and a re-publish clears stale ones.
func TestTokenDisabledWithoutRotation(t *testing.T) {
	SetRegistryMetrics(map[string]Entry{
		"t-live": {ID: "edge-live"},
		"t-dead": {ID: "edge-dead", Disabled: true},
	})
	if v := testutil.ToFloat64(tokenDisabledNoRotation.WithLabelValues("edge-dead")); v != 1 {
		t.Errorf("blacklisted id must flag without_rotation=1, got %v", v)
	}
	if c := testutil.CollectAndCount(tokenDisabledNoRotation); c != 1 {
		t.Errorf("only the disabled id gets a series, got %d", c)
	}
	// Removing the tombstone (registry no longer lists it) clears the flag.
	SetRegistryMetrics(map[string]Entry{"t-live": {ID: "edge-live"}})
	if c := testutil.CollectAndCount(tokenDisabledNoRotation); c != 0 {
		t.Errorf("removing the tombstone must clear the flag, got %d series", c)
	}
}

// edge_ca_rotation_stuck is 0 outside overlap, 0 inside overlap before the deadline, and 1
// once the overlap outlives the deadline. The overlap-start is taken from the annotation
// timestamp (restart-immune), and a re-observe at the same start does not move the clock.
func TestRotationStuckGauge(t *testing.T) {
	t.Cleanup(func() { SetRotationOverlap(false, 0); SetRotationStuckDeadline(0) })

	SetRotationStuckDeadline(time.Hour)
	SetRotationOverlap(false, 0)
	if v := testutil.ToFloat64(rotationStuck); v != 0 {
		t.Errorf("not in overlap ⇒ 0, got %v", v)
	}
	// Overlap that began 2h ago (annotation start), deadline 1h ⇒ stuck. This is the
	// RESTART-IMMUNE path: the age comes from the persisted start, not first-observed time.
	twoHoursAgo := time.Now().Add(-2 * time.Hour).Unix()
	SetRotationOverlap(true, twoHoursAgo)
	if v := testutil.ToFloat64(rotationStuck); v != 1 {
		t.Errorf("overlap started past the deadline ⇒ 1, got %v", v)
	}
	// A fresh restart re-reads the SAME annotation start → still correctly stuck (the bug this
	// folds: a restart used to reset the clock to now and falsely read 0).
	before := rotationOverlapSince.Load()
	SetRotationOverlap(true, twoHoursAgo)
	if rotationOverlapSince.Load() != before {
		t.Error("re-observing the same overlap start must be idempotent (restart-immune)")
	}
	if v := testutil.ToFloat64(rotationStuck); v != 1 {
		t.Error("re-observe after 'restart' must still read stuck")
	}
	// A recent overlap within the deadline ⇒ not yet stuck.
	SetRotationOverlap(true, time.Now().Add(-1*time.Minute).Unix())
	if v := testutil.ToFloat64(rotationStuck); v != 0 {
		t.Errorf("fresh overlap within the deadline ⇒ 0, got %v", v)
	}
	// Legacy Secret (no started annotation, startedUnix=0) ⇒ first-observed fallback (recent ⇒ 0).
	SetRotationOverlap(false, 0)
	SetRotationOverlap(true, 0)
	if v := testutil.ToFloat64(rotationStuck); v != 0 {
		t.Errorf("legacy fallback (just observed) ⇒ 0, got %v", v)
	}
	// Deadline disabled (0) ⇒ never stuck even when long in overlap.
	SetRotationOverlap(true, time.Now().Add(-100*time.Hour).Unix())
	SetRotationStuckDeadline(0)
	if v := testutil.ToFloat64(rotationStuck); v != 0 {
		t.Errorf("deadline disabled ⇒ 0, got %v", v)
	}
}

// AuthzGeneration is replica-deterministic (the blacklist-barrier pin) and CHANGES when an
// id's disabled flag flips — so a revoke moves it, letting the interlock prove the blacklist
// converged. Order-independent (it sorts), id-only (tokens/domains don't perturb it).
func TestAuthzGenerationDeterministicAndRevokeSensitive(t *testing.T) {
	base := map[string]Entry{
		"t1": {ID: "edge-a"},
		"t2": {ID: "edge-b"},
	}
	reordered := map[string]Entry{
		"t2": {ID: "edge-b"},
		"t1": {ID: "edge-a"},
	}
	if AuthzGeneration(base) != AuthzGeneration(reordered) {
		t.Error("authz generation must be order-independent (replica-deterministic)")
	}
	revoked := map[string]Entry{
		"t1": {ID: "edge-a"},
		"t2": {ID: "edge-b", Disabled: true}, // the revoke
	}
	if AuthzGeneration(base) == AuthzGeneration(revoked) {
		t.Error("disabling an id must change the authz generation (the blacklist-barrier signal)")
	}
	// A non-data-plane entry (no id) and domain changes must NOT perturb it.
	withNoise := map[string]Entry{
		"t1": {ID: "edge-a", Domains: []string{"x.com"}},
		"t2": {ID: "edge-b"},
		"t3": {Domains: []string{"y.com"}}, // no id → ignored
	}
	if AuthzGeneration(base) != AuthzGeneration(withNoise) {
		t.Error("only id+disabled may affect the authz generation")
	}
}
