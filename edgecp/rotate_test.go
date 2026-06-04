package edgecp

import (
	"context"
	"strconv"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
)

// populatedCAStub returns a fakeRW holding a single-CA Secret (the pre-rotation
// state) plus the OLD cert/key for assertions.
func populatedCAStub(t *testing.T) (f *fakeRW, oldCert, oldKey []byte) {
	t.Helper()
	oldCert, oldKey = mustGenerateCA(t)
	stub := emptyStub("ns", "parapet-edge-ca")
	stub.Data["tls.crt"] = oldCert
	stub.Data["tls.key"] = oldKey
	stub.Annotations = map[string]string{caGenerationAnnotation: "old-id"}
	f = &fakeRW{secrets: map[string]*v1.Secret{"ns/parapet-edge-ca": stub}}
	return f, oldCert, oldKey
}

func TestRotateCAAddsNewToBundle(t *testing.T) {
	f, oldCert, oldKey := populatedCAStub(t)

	bundle, err := RotateCA(context.Background(), f, "ns", "parapet-edge-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, n, _ := reencodeCertBundle(bundle); n != 2 {
		t.Errorf("returned bundle should hold 2 certs, got %d", n)
	}

	s := f.secrets["ns/parapet-edge-ca"]
	if _, n, _ := reencodeCertBundle(s.Data["tls.crt"]); n != 2 {
		t.Errorf("tls.crt should be OLD++NEW (2 certs), got %d", n)
	}
	// OLD stays first (so the active OLD key still matches block[0]) and tls.key is
	// untouched; the NEW key is staged separately.
	if fps := certBundleFPs(s.Data["tls.crt"]); len(fps) != 2 || fps[0] != fpOf(t, oldCert) {
		t.Error("OLD cert must remain first in the bundle")
	}
	if string(s.Data["tls.key"]) != string(oldKey) {
		t.Error("tls.key (active) must stay the OLD key during overlap")
	}
	if len(s.Data[caNewKeyField]) == 0 {
		t.Error("NEW key must be staged in tls-new.key")
	}
	if s.Annotations[caRotationPhaseAnnotation] != caPhaseOverlap {
		t.Errorf("phase = %q, want overlap", s.Annotations[caRotationPhaseAnnotation])
	}
	if s.Annotations[caActiveAnnotation] != caActiveOld {
		t.Errorf("active = %q, want old", s.Annotations[caActiveAnnotation])
	}
	if s.Annotations[caGenerationAnnotation] == "" {
		t.Error("anti-regeneration guard must remain stamped (never blanked)")
	}
	// The overlap-start timestamp is stamped (feeds the restart-immune rotation_stuck gauge).
	if started, err := strconv.ParseInt(s.Annotations[caRotationStartedAnnotation], 10, 64); err != nil || started <= 0 {
		t.Errorf("rotation-started annotation must be a positive unix time, got %q (err=%v)", s.Annotations[caRotationStartedAnnotation], err)
	}
}

func TestRotateCAIdempotent(t *testing.T) {
	f, _, _ := populatedCAStub(t)

	bundle1, err := RotateCA(context.Background(), f, "ns", "parapet-edge-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	callsAfterFirst := f.updateCalls

	bundle2, err := RotateCA(context.Background(), f, "ns", "parapet-edge-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// No third cert, no write, same bundle.
	if _, n, _ := reencodeCertBundle(f.secrets["ns/parapet-edge-ca"].Data["tls.crt"]); n != 2 {
		t.Errorf("a re-run must not append a third cert, got %d", n)
	}
	if f.updateCalls != callsAfterFirst {
		t.Errorf("idempotent re-run must not write, updateCalls %d → %d", callsAfterFirst, f.updateCalls)
	}
	if string(bundle1) != string(bundle2) {
		t.Error("idempotent re-run must return the existing overlap bundle")
	}
}

func TestRotateCAConflictReEvaluates(t *testing.T) {
	f, oldCert, oldKey := populatedCAStub(t)
	f.conflictNext = true
	// On the (simulated) CAS conflict, another rotator already moved the Secret to
	// overlap. The loser must adopt it (end at 2 certs), not append a third.
	newCert2, newKey2 := mustGenerateCA(t)
	f.onConflict = func() {
		s := emptyStub("ns", "parapet-edge-ca")
		s.Data["tls.crt"] = append(append([]byte(nil), oldCert...), newCert2...)
		s.Data["tls.key"] = oldKey
		s.Data[caNewKeyField] = newKey2
		s.Annotations = map[string]string{
			caRotationPhaseAnnotation: caPhaseOverlap,
			caActiveAnnotation:        caActiveOld,
			caGenerationAnnotation:    "winner",
		}
		f.secrets["ns/parapet-edge-ca"] = s
	}

	if _, err := RotateCA(context.Background(), f, "ns", "parapet-edge-ca", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, n, _ := reencodeCertBundle(f.secrets["ns/parapet-edge-ca"].Data["tls.crt"]); n != 2 {
		t.Errorf("after a conflict-adopt the bundle must be exactly 2 certs, got %d", n)
	}
}

func TestRotateCARefusesUnpopulated(t *testing.T) {
	f := &fakeRW{secrets: map[string]*v1.Secret{"ns/parapet-edge-ca": emptyStub("ns", "parapet-edge-ca")}}
	if _, err := RotateCA(context.Background(), f, "ns", "parapet-edge-ca", time.Hour); err == nil {
		t.Error("rotation must refuse a virgin/empty CA (only runs on an existing CA)")
	}
}

func TestRotateCAFatalOnMissing(t *testing.T) {
	f := &fakeRW{secrets: map[string]*v1.Secret{}}
	if _, err := RotateCA(context.Background(), f, "ns", "parapet-edge-ca", time.Hour); err == nil {
		t.Error("a missing CA Secret must be a fatal error (no rotation)")
	}
}

func TestRotateCABundleRoundTrips(t *testing.T) {
	f, _, _ := populatedCAStub(t)
	if _, err := RotateCA(context.Background(), f, "ns", "parapet-edge-ca", time.Hour); err != nil {
		t.Fatal(err)
	}
	s := f.secrets["ns/parapet-edge-ca"]
	crt := s.Data["tls.crt"]

	// Both halves are usable: a signer on the OLD key and one on the NEW key each
	// mint a leaf that verifies against the served OLD++NEW bundle.
	oldSigner, _, err := NewProvidedSignerActive(crt, s.Data["tls.key"], "", time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newSigner, _, err := NewProvidedSignerActive(crt, s.Data[caNewKeyField], "", time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for name, sg := range map[string]*Signer{"old": oldSigner, "new": newSigner} {
		chainPEM, _, _, err := sg.Sign(mkLeafKey(t).Public(), "edge-1")
		if err != nil {
			t.Fatalf("%s signer: %v", name, err)
		}
		if !verifiesUnder(t, chainPEM, crt) {
			t.Errorf("%s signer: leaf must verify against the OLD++NEW bundle", name)
		}
	}
}
