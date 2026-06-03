package edgecp

import (
	"context"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// testReloader builds a SignerReloader whose secret list is backed by *secs (so a
// test can mutate the Secret between reloads to simulate a rotation).
func testReloader(srv *Server, secs *[]v1.Secret) *SignerReloader {
	r := NewSignerReloader(srv, "ns", "parapet-edge-ca", time.Hour, time.Minute)
	r.list = func(_ context.Context, _ string) ([]v1.Secret, error) { return *secs, nil }
	return r
}

func caSecretObj(data map[string][]byte, annotations map[string]string) v1.Secret {
	return v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "parapet-edge-ca", Namespace: "ns", Annotations: annotations},
		Data:       data,
	}
}

// gen reads the current generation (0 if no signer). In-package test access.
func srvGen(s *Server) uint64 {
	if st := s.signerState.Load(); st != nil {
		return st.gen
	}
	return 0
}

func TestSignerReloaderPicksUpRotation(t *testing.T) {
	oldCert, oldKey := mustGenerateCA(t)
	secs := []v1.Secret{caSecretObj(map[string][]byte{"tls.crt": oldCert, "tls.key": oldKey}, nil)}

	srv := NewServer(NewCertStore(), NewAuthz(nil))
	r := testReloader(srv, &secs)
	if err := r.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !srv.SignerLoaded() {
		t.Fatal("signer should load from a single-CA secret")
	}
	gen1, caid1 := srvGen(srv), srv.CurrentCAID()

	// Rotate: flip the Secret to OLD++NEW overlap.
	newCert, newKey := mustGenerateCA(t)
	secs[0].Data["tls.crt"] = append(append([]byte(nil), oldCert...), newCert...)
	secs[0].Data[caNewKeyField] = newKey
	secs[0].Annotations = map[string]string{caRotationPhaseAnnotation: caPhaseOverlap, caActiveAnnotation: caActiveOld}

	if err := r.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srvGen(srv) <= gen1 {
		t.Errorf("generation should advance on rotation, %d → %d", gen1, srvGen(srv))
	}
	if srv.CurrentCAID() == caid1 {
		t.Error("ca_id should flip when the bundle widens to OLD++NEW")
	}
}

func TestSignerReloaderNoOpReList(t *testing.T) {
	oldCert, oldKey := mustGenerateCA(t)
	secs := []v1.Secret{caSecretObj(map[string][]byte{"tls.crt": oldCert, "tls.key": oldKey}, nil)}

	srv := NewServer(NewCertStore(), NewAuthz(nil))
	r := testReloader(srv, &secs)
	if err := r.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	gen1 := srvGen(srv)

	// Re-running on a byte-identical bundle must NOT churn the generation.
	if err := r.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srvGen(srv) != gen1 {
		t.Errorf("no-op re-list must not advance generation, %d → %d", gen1, srvGen(srv))
	}
}

func TestSignerReloaderActiveNewBranch(t *testing.T) {
	oldCert, oldKey := mustGenerateCA(t)
	newCert, newKey := mustGenerateCA(t)
	overlap := append(append([]byte(nil), oldCert...), newCert...)
	secs := []v1.Secret{caSecretObj(
		map[string][]byte{"tls.crt": overlap, "tls.key": oldKey, caNewKeyField: newKey},
		map[string]string{caRotationPhaseAnnotation: caPhaseOverlap, caActiveAnnotation: caActiveNew},
	)}

	srv := NewServer(NewCertStore(), NewAuthz(nil))
	r := testReloader(srv, &secs)
	if err := r.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !srv.SignerLoaded() {
		t.Fatal("signer should load with active=new")
	}
	// The active signer signs under NEW (verifies against NEW alone, not OLD alone).
	sg := srv.signerState.Load().sg
	chainPEM, _, _, err := sg.Sign(mkLeafKey(t).Public(), "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	if !verifiesUnder(t, chainPEM, newCert) {
		t.Error("active=new must sign under the NEW CA")
	}
	if verifiesUnder(t, chainPEM, oldCert) {
		t.Error("active=new must NOT sign under OLD")
	}
}

func TestSignerReloaderContradictoryAnnotationKeepsLastGood(t *testing.T) {
	oldCert, oldKey := mustGenerateCA(t)
	secs := []v1.Secret{caSecretObj(map[string][]byte{"tls.crt": oldCert, "tls.key": oldKey}, nil)}

	srv := NewServer(NewCertStore(), NewAuthz(nil))
	r := testReloader(srv, &secs)
	if err := r.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	gen1, caid1 := srvGen(srv), srv.CurrentCAID()

	// Contradiction: active=new with a staged key matching NEITHER cert in the
	// overlap → the candidate Signer fails to build → keep last-good (no churn).
	newCert, _ := mustGenerateCA(t)
	_, strayKey := mustGenerateCA(t)
	secs[0].Data["tls.crt"] = append(append([]byte(nil), oldCert...), newCert...)
	secs[0].Data[caNewKeyField] = strayKey
	secs[0].Annotations = map[string]string{caRotationPhaseAnnotation: caPhaseOverlap, caActiveAnnotation: caActiveNew}

	if err := r.reload(context.Background()); err != nil {
		t.Fatal(err) // reload itself doesn't error; it logs + keeps last-good
	}
	if srvGen(srv) != gen1 || srv.CurrentCAID() != caid1 {
		t.Error("a contradictory annotation/key must keep the last-good signer (no generation change)")
	}
}

func TestSignerReloaderAbsentSecretKeepsUnloaded(t *testing.T) {
	secs := []v1.Secret{} // CA not provisioned yet
	srv := NewServer(NewCertStore(), NewAuthz(nil))
	r := testReloader(srv, &secs)
	if err := r.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srv.SignerLoaded() {
		t.Error("no signer should load when the CA secret is absent")
	}
}
