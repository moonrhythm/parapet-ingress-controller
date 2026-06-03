package edgecp

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// fakeRW is an in-memory SecretRW with optional one-shot Update conflict (to
// exercise the CAS loser-adopts path) and an update counter (to prove adopt is a
// no-op write).
type fakeRW struct {
	mu           sync.Mutex
	secrets      map[string]*v1.Secret
	updateCalls  int
	conflictNext bool
	onConflict   func() // mutate state so the post-conflict re-GET adopts the winner
}

func (f *fakeRW) GetSecret(_ context.Context, ns, name string) (*v1.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.secrets[ns+"/"+name]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, name)
	}
	return s.DeepCopy(), nil
}

func (f *fakeRW) UpdateSecret(_ context.Context, ns string, s *v1.Secret) (*v1.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updateCalls++
	if f.conflictNext {
		f.conflictNext = false
		if f.onConflict != nil {
			f.onConflict()
		}
		return nil, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, s.Name, fmt.Errorf("rv changed"))
	}
	f.secrets[ns+"/"+s.Name] = s.DeepCopy()
	return s.DeepCopy(), nil
}

func emptyStub(ns, name string) *v1.Secret {
	return &v1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Data: map[string][]byte{}}
}

func TestGenerateCAShape(t *testing.T) {
	certPEM, keyPEM := mustGenerateCA(t)
	block, _ := pem.Decode(certPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || !ca.MaxPathLenZero {
		t.Error("want IsCA + MaxPathLen 0")
	}
	if ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("want KeyUsageCertSign")
	}
	if len(ca.PermittedURIDomains) != 1 || ca.PermittedURIDomains[0] != SANTrustDomain {
		t.Errorf("want NameConstraints PermittedURIDomains=[%s], got %v", SANTrustDomain, ca.PermittedURIDomains)
	}
	// A generated CA must pass provided-mode validation with NO warnings.
	if _, warnings, err := NewProvidedSigner(certPEM, keyPEM, time.Hour, time.Minute); err != nil || len(warnings) != 0 {
		t.Errorf("generated CA should validate cleanly: err=%v warnings=%v", err, warnings)
	}
}

func TestEnsureCAGeneratesIntoVirginStub(t *testing.T) {
	f := &fakeRW{secrets: map[string]*v1.Secret{"ns/parapet-edge-ca": emptyStub("ns", "parapet-edge-ca")}}
	certPEM, keyPEM, err := EnsureCA(context.Background(), f, "ns", "parapet-edge-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !validCAKeypair(certPEM, keyPEM) {
		t.Fatal("EnsureCA returned an invalid CA keypair")
	}
	// The stub is now populated with the keypair AND the guard annotation.
	s := f.secrets["ns/parapet-edge-ca"]
	if len(s.Data["tls.crt"]) == 0 || len(s.Data["tls.key"]) == 0 {
		t.Error("stub not populated")
	}
	if _, ok := s.Annotations[caGenerationAnnotation]; !ok {
		t.Error("missing anti-regeneration guard annotation")
	}
}

func TestEnsureCAAdoptsAndDoesNotRewrite(t *testing.T) {
	certPEM, keyPEM := mustGenerateCA(t)
	stub := emptyStub("ns", "parapet-edge-ca")
	stub.Data["tls.crt"] = certPEM
	stub.Data["tls.key"] = keyPEM
	stub.Annotations = map[string]string{caGenerationAnnotation: "x"}
	f := &fakeRW{secrets: map[string]*v1.Secret{"ns/parapet-edge-ca": stub}}

	gotCert, _, err := EnsureCA(context.Background(), f, "ns", "parapet-edge-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotCert) != string(certPEM) {
		t.Error("adopt must return the EXISTING CA, not a fresh one")
	}
	if f.updateCalls != 0 {
		t.Errorf("adopt must not write the Secret, got %d updates", f.updateCalls)
	}
}

func TestEnsureCANeverRegeneratesABlankedCA(t *testing.T) {
	// Guard annotation present but data blanked = a populated CA was wiped. Must
	// NOT regenerate (that would distrust the whole fleet).
	stub := emptyStub("ns", "parapet-edge-ca")
	stub.Annotations = map[string]string{caGenerationAnnotation: "deadbeef"}
	f := &fakeRW{secrets: map[string]*v1.Secret{"ns/parapet-edge-ca": stub}}
	if _, _, err := EnsureCA(context.Background(), f, "ns", "parapet-edge-ca", time.Hour); err == nil {
		t.Fatal("a guarded-but-empty CA secret must be a hard error, not a regenerate")
	}
	if f.updateCalls != 0 {
		t.Error("must not write on the anomaly path")
	}
}

func TestEnsureCAFatalOnMissingStub(t *testing.T) {
	f := &fakeRW{secrets: map[string]*v1.Secret{}}
	if _, _, err := EnsureCA(context.Background(), f, "ns", "parapet-edge-ca", time.Hour); err == nil {
		t.Fatal("a missing CA stub must be a fatal config error (no broad create)")
	}
}

func TestEnsureCAConflictAdoptsWinner(t *testing.T) {
	winnerCert, winnerKey := mustGenerateCA(t)
	f := &fakeRW{
		secrets:      map[string]*v1.Secret{"ns/parapet-edge-ca": emptyStub("ns", "parapet-edge-ca")},
		conflictNext: true,
	}
	// On the (simulated) CAS conflict, another bootstrapper has populated the CA.
	f.onConflict = func() {
		s := emptyStub("ns", "parapet-edge-ca")
		s.Data["tls.crt"] = winnerCert
		s.Data["tls.key"] = winnerKey
		s.Annotations = map[string]string{caGenerationAnnotation: "winner"}
		f.secrets["ns/parapet-edge-ca"] = s
	}
	gotCert, _, err := EnsureCA(context.Background(), f, "ns", "parapet-edge-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotCert) != string(winnerCert) {
		t.Error("on CAS conflict, the loser must adopt the winner's CA")
	}
}

func mustGenerateCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	c, k, err := GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}
