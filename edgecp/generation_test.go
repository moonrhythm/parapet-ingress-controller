package edgecp

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	v1 "k8s.io/api/core/v1"
)

// The monotonic floor rejects a generation <= the served one (an out-of-order re-list or
// a not-advanced provided-CA rotation), keeps last-good, and counts the rejection.
func TestSetSignerMonotonicFloor(t *testing.T) {
	certA, keyA := mustGenerateCA(t)
	certB, keyB := mustGenerateCA(t)
	sgA, _, _ := NewProvidedSigner(certA, keyA, 0, 0)
	sgB, _, _ := NewProvidedSigner(certB, keyB, 0, 0)

	srv := NewServer(NewCertStore(), NewAuthz(nil))
	before := testutil.ToFloat64(signerFloored)

	srv.SetSigner(sgA, 5)
	if srvGen(srv) != 5 || srv.CurrentCAID() != sgA.CAID() {
		t.Fatalf("first install: gen=%d caid=%s", srvGen(srv), srv.CurrentCAID())
	}
	srv.SetSigner(sgB, 3) // older → floored
	if srvGen(srv) != 5 || srv.CurrentCAID() != sgA.CAID() {
		t.Error("an older generation must be floored (keep last-good)")
	}
	srv.SetSigner(sgB, 5) // equal → floored (provided-CA rotation that didn't advance)
	if srvGen(srv) != 5 || srv.CurrentCAID() != sgA.CAID() {
		t.Error("an equal generation must be floored")
	}
	if got := testutil.ToFloat64(signerFloored); got != before+2 {
		t.Errorf("floored counter: %v, want +2", got-before)
	}
	srv.SetSigner(sgB, 6) // newer → applied
	if srvGen(srv) != 6 || srv.CurrentCAID() != sgB.CAID() {
		t.Error("a newer generation must apply")
	}
}

// Two independent reloaders over the SAME CA-Secret resourceVersion compute the
// byte-identical generation — replica-identical by construction (etcd's global revision),
// replacing the desync-prone per-process prev+1 counter.
func TestReplicaIdenticalGeneration(t *testing.T) {
	oldCert, oldKey := mustGenerateCA(t)
	secs := []v1.Secret{caSecretObj(map[string][]byte{"tls.crt": oldCert, "tls.key": oldKey}, nil)}
	secs[0].ResourceVersion = "424242"

	srv1, srv2 := NewServer(NewCertStore(), NewAuthz(nil)), NewServer(NewCertStore(), NewAuthz(nil))
	if err := testReloader(srv1, &secs).reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := testReloader(srv2, &secs).reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srvGen(srv1) != 424242 || srvGen(srv2) != 424242 {
		t.Errorf("both replicas must derive gen=424242, got %d and %d", srvGen(srv1), srvGen(srv2))
	}
	if srv1.CurrentCAID() != srv2.CurrentCAID() {
		t.Error("both replicas must serve the same ca_id")
	}
}

// A non-numeric resourceVersion freezes the signer at last-good (fail-closed) and raises
// the alertable gauge; a subsequent numeric RV recovers and clears the gauge.
func TestSignerReloadRVUnparseableKeepsLastGood(t *testing.T) {
	oldCert, oldKey := mustGenerateCA(t)
	secs := []v1.Secret{caSecretObj(map[string][]byte{"tls.crt": oldCert, "tls.key": oldKey}, nil)}
	srv := NewServer(NewCertStore(), NewAuthz(nil))
	r := testReloader(srv, &secs)
	if err := r.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	gen1, caid1 := srvGen(srv), srv.CurrentCAID()

	// Opaque RV + a changed bundle: must NOT swap (fail-closed), gauge → 1.
	newCert, newKey := mustGenerateCA(t)
	secs[0].Data["tls.crt"] = append(append([]byte(nil), oldCert...), newCert...)
	secs[0].Data[caNewKeyField] = newKey
	secs[0].Annotations = map[string]string{caRotationPhaseAnnotation: caPhaseOverlap, caActiveAnnotation: caActiveOld}
	secs[0].ResourceVersion = "opaque-rv"
	if err := r.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srvGen(srv) != gen1 || srv.CurrentCAID() != caid1 {
		t.Error("an unparseable resourceVersion must keep last-good (never swap on a gen we can't order)")
	}
	if testutil.ToFloat64(signerRVUnparsed) != 1 {
		t.Error("signerRVUnparsed gauge must be 1 while the RV is opaque")
	}

	// Recover: a numeric RV applies the (still-changed) bundle and clears the gauge.
	secs[0].ResourceVersion = "500"
	if err := r.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srvGen(srv) != 500 || srv.CurrentCAID() == caid1 {
		t.Error("a numeric RV must recover and apply the changed bundle")
	}
	if testutil.ToFloat64(signerRVUnparsed) != 0 {
		t.Error("signerRVUnparsed gauge must clear to 0 once the RV parses")
	}
}

// A metadata-only write (RV bumped, tls.crt identical) must NOT advance the generation —
// the ca_id no-churn gate suppresses it, so the core has nothing to re-apply.
func TestMetadataOnlyPUTNoChurn(t *testing.T) {
	oldCert, oldKey := mustGenerateCA(t)
	secs := []v1.Secret{caSecretObj(map[string][]byte{"tls.crt": oldCert, "tls.key": oldKey}, nil)}
	srv := NewServer(NewCertStore(), NewAuthz(nil))
	r := testReloader(srv, &secs)
	if err := r.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	gen1, caid1 := srvGen(srv), srv.CurrentCAID()

	// Bump only the RV (e.g. a label/annotation write) — same bundle, same ca_id.
	secs[0].ResourceVersion = "999"
	if err := r.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srvGen(srv) != gen1 || srv.CurrentCAID() != caid1 {
		t.Errorf("a metadata-only write must not advance generation (%d→%d) — the ca_id gate suppresses it", gen1, srvGen(srv))
	}
}
