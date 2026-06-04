package edgecp

import (
	"context"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
)

// overlapStub returns a fakeRW in the OLD++NEW overlap (active=old) by running RotateCA on
// a populated single-CA Secret, plus the OLD cert and the NEW cert's fingerprint.
func overlapStub(t *testing.T) (f *fakeRW, oldCert []byte, newFP string) {
	t.Helper()
	f, oldCert, _ = populatedCAStub(t)
	if _, err := RotateCA(context.Background(), f, "ns", "parapet-edge-ca", time.Hour); err != nil {
		t.Fatal(err)
	}
	fps := certBundleFPs(f.secrets["ns/parapet-edge-ca"].Data["tls.crt"])
	if len(fps) != 2 {
		t.Fatalf("overlap should have 2 certs, got %d", len(fps))
	}
	return f, oldCert, fps[1] // NEW is last
}

// sec is a short accessor for the live CA Secret.
func sec(f *fakeRW) *v1.Secret { return f.secrets["ns/parapet-edge-ca"] }

func TestSetActiveNewFlips(t *testing.T) {
	f, _, newFP := overlapStub(t)

	if _, err := SetActiveNew(context.Background(), f, "ns", "parapet-edge-ca", newFP); err != nil {
		t.Fatal(err)
	}
	s := sec(f)
	if s.Annotations[caActiveAnnotation] != caActiveNew {
		t.Errorf("active = %q, want new", s.Annotations[caActiveAnnotation])
	}
	// Non-destructive: the bundle is byte-identical (still OLD++NEW), tls.key + the staged
	// NEW key are untouched.
	if _, n, _ := reencodeCertBundle(s.Data["tls.crt"]); n != 2 {
		t.Errorf("flip must keep both certs, got %d", n)
	}
	if len(s.Data[caNewKeyField]) == 0 {
		t.Error("flip must keep the staged NEW key (still needed until trim)")
	}
	// The reloader's active=new selection (NEW key + NEW fp) now signs under NEW.
	sg, _, err := NewProvidedSignerActive(s.Data["tls.crt"], s.Data[caNewKeyField], newFP, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if sg.ActiveFP() != newFP {
		t.Errorf("post-flip active fp = %q, want NEW %q", sg.ActiveFP(), newFP)
	}
}

func TestSetActiveNewIdempotent(t *testing.T) {
	f, _, newFP := overlapStub(t)
	if _, err := SetActiveNew(context.Background(), f, "ns", "parapet-edge-ca", newFP); err != nil {
		t.Fatal(err)
	}
	calls := f.updateCalls
	if _, err := SetActiveNew(context.Background(), f, "ns", "parapet-edge-ca", newFP); err != nil {
		t.Fatal(err)
	}
	if f.updateCalls != calls {
		t.Errorf("idempotent re-run must not write, updateCalls %d → %d", calls, f.updateCalls)
	}
}

func TestSetActiveNewPinMismatch(t *testing.T) {
	f, _, _ := overlapStub(t)
	if _, err := SetActiveNew(context.Background(), f, "ns", "parapet-edge-ca", "deadbeef"); err == nil {
		t.Error("a wrong NEW-fp pin must refuse the flip")
	}
	if sec(f).Annotations[caActiveAnnotation] != caActiveOld {
		t.Error("a refused flip must leave active=old")
	}
}

func TestSetActiveNewRefusesNonOverlap(t *testing.T) {
	f, _, _ := populatedCAStub(t) // single-CA, never rotated
	if _, err := SetActiveNew(context.Background(), f, "ns", "parapet-edge-ca", ""); err == nil {
		t.Error("flip must refuse a non-overlap (single-CA) Secret")
	}
}

func TestTrimCADropsOldAndSeversOldLeaves(t *testing.T) {
	f, oldCert, newFP := overlapStub(t)
	s := sec(f)

	// Capture an OLD-signed leaf minted during the overlap (active=old) BEFORE the drop.
	oldSigner, _, err := NewProvidedSignerActive(s.Data["tls.crt"], s.Data["tls.key"], fpOf(t, oldCert), time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	oldLeafChain, _, _, err := oldSigner.Sign(mkLeafKey(t).Public(), "edge-old")
	if err != nil {
		t.Fatal(err)
	}

	// Flip then trim (the required order).
	if _, err := SetActiveNew(context.Background(), f, "ns", "parapet-edge-ca", newFP); err != nil {
		t.Fatal(err)
	}
	newBundle, err := TrimCA(context.Background(), f, "ns", "parapet-edge-ca", newFP)
	if err != nil {
		t.Fatal(err)
	}

	s = sec(f)
	fps := certBundleFPs(s.Data["tls.crt"])
	if len(fps) != 1 || fps[0] != newFP {
		t.Fatalf("trimmed tls.crt must be NEW-only, got fps=%v want [%s]", fps, newFP)
	}
	if len(s.Data[caNewKeyField]) != 0 {
		t.Error("trim must delete the staged NEW key field")
	}
	if !validCAKeypair(s.Data["tls.crt"], s.Data["tls.key"]) {
		t.Error("post-trim tls.key must match the surviving NEW cert")
	}
	if s.Annotations[caRotationPhaseAnnotation] != caPhaseTrimmed {
		t.Errorf("phase = %q, want trimmed", s.Annotations[caRotationPhaseAnnotation])
	}
	if s.Annotations[caActiveAnnotation] != caActiveOld {
		t.Errorf("active = %q, want old (single-CA default)", s.Annotations[caActiveAnnotation])
	}
	if s.Annotations[caGenerationAnnotation] == "" {
		t.Error("anti-regeneration guard must remain stamped after trim")
	}

	// THE load-bearing property: an OLD-signed leaf no longer verifies against the trimmed
	// NEW-only bundle (the revoked/un-re-minted edge is severed), while a fresh NEW leaf does.
	if verifiesUnder(t, oldLeafChain, newBundle) {
		t.Error("an OLD-signed leaf must NOT verify against the trimmed NEW-only CA (it must be severed)")
	}
	newSigner, _, err := NewProvidedSignerActive(s.Data["tls.crt"], s.Data["tls.key"], newFP, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newLeaf, _, _, err := newSigner.Sign(mkLeafKey(t).Public(), "edge-new")
	if err != nil {
		t.Fatal(err)
	}
	if !verifiesUnder(t, newLeaf, newBundle) {
		t.Error("a NEW-signed leaf must verify against the trimmed NEW-only CA")
	}
}

func TestTrimCARefusesActiveOld(t *testing.T) {
	f, _, newFP := overlapStub(t) // still active=old (no flip)
	if _, err := TrimCA(context.Background(), f, "ns", "parapet-edge-ca", newFP); err == nil {
		t.Error("trim must refuse while active=old (dropping OLD would orphan the signing key)")
	}
	if _, n, _ := reencodeCertBundle(sec(f).Data["tls.crt"]); n != 2 {
		t.Error("a refused trim must leave both certs")
	}
}

func TestTrimCARequiresFP(t *testing.T) {
	f, _, newFP := overlapStub(t)
	if _, err := SetActiveNew(context.Background(), f, "ns", "parapet-edge-ca", newFP); err != nil {
		t.Fatal(err)
	}
	if _, err := TrimCA(context.Background(), f, "ns", "parapet-edge-ca", ""); err == nil {
		t.Error("trim must require the expected NEW fp (no blind destructive drop)")
	}
}

func TestTrimCAPinMismatch(t *testing.T) {
	f, _, newFP := overlapStub(t)
	if _, err := SetActiveNew(context.Background(), f, "ns", "parapet-edge-ca", newFP); err != nil {
		t.Fatal(err)
	}
	if _, err := TrimCA(context.Background(), f, "ns", "parapet-edge-ca", "deadbeef"); err == nil {
		t.Error("a wrong NEW-fp pin must refuse the trim")
	}
	if _, n, _ := reencodeCertBundle(sec(f).Data["tls.crt"]); n != 2 {
		t.Error("a refused trim must leave both certs")
	}
}

func TestTrimCAIdempotent(t *testing.T) {
	f, _, newFP := overlapStub(t)
	if _, err := SetActiveNew(context.Background(), f, "ns", "parapet-edge-ca", newFP); err != nil {
		t.Fatal(err)
	}
	if _, err := TrimCA(context.Background(), f, "ns", "parapet-edge-ca", newFP); err != nil {
		t.Fatal(err)
	}
	calls := f.updateCalls
	bundle2, err := TrimCA(context.Background(), f, "ns", "parapet-edge-ca", newFP)
	if err != nil {
		t.Fatal(err)
	}
	if f.updateCalls != calls {
		t.Errorf("idempotent re-trim must not write, updateCalls %d → %d", calls, f.updateCalls)
	}
	if fps := certBundleFPs(bundle2); len(fps) != 1 || fps[0] != newFP {
		t.Errorf("re-trim must return the NEW-only bundle, got %v", fps)
	}
}
