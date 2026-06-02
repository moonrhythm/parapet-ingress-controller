package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/edgecp"
)

func caPEMFor(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "edge-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		PermittedURIDomains:   []string{edgecp.SANTrustDomain},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestManagerForwardOnlyAndFailStatic(t *testing.T) {
	caPEM, _ := caPEMFor(t)
	m := NewManager()

	if m.ClientCAs() != nil {
		t.Fatal("pool should be nil before first apply")
	}
	if err := m.apply(Bundle{Generation: 5, CAPEM: caPEM, CAID: "a"}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if m.Generation() != 5 || m.ClientCAs() == nil {
		t.Fatal("first apply did not take")
	}

	// Rollback (lower) and replay (equal) are rejected; the live pool is unchanged.
	if err := m.apply(Bundle{Generation: 3, CAPEM: caPEM}); err == nil {
		t.Error("rollback to lower generation must be rejected")
	}
	if err := m.apply(Bundle{Generation: 5, CAPEM: caPEM}); err == nil {
		t.Error("replay of equal generation must be rejected")
	}
	if m.Generation() != 5 {
		t.Error("a rejected bundle must not change generation")
	}

	// Strict parse: a non-empty but cert-less ca_pem is rejected, last-good kept.
	prev := m.ClientCAs()
	if err := m.apply(Bundle{Generation: 6, CAPEM: []byte("garbage")}); err == nil {
		t.Error("ca_pem with no certs must be rejected")
	}
	if m.Generation() != 5 || m.ClientCAs() != prev {
		t.Error("a rejected reload must keep last-good")
	}

	// A higher generation applies.
	if err := m.apply(Bundle{Generation: 6, CAPEM: caPEM, CAID: "b"}); err != nil {
		t.Fatalf("forward apply: %v", err)
	}
	if m.Generation() != 6 || m.CAID() != "b" {
		t.Error("forward apply did not take")
	}
}

// TestTrustBundleOverTLSEndToEnd runs the real edgecp trust-bundle handler over a
// TLS httptest server, has the core's trust Client fetch it with MANDATORY server
// verification, applies it, and confirms the resulting pool verifies an edge leaf
// the same CA signs — i.e. the full core↔CP trust path with no token.
func TestTrustBundleOverTLSEndToEnd(t *testing.T) {
	caCertPEM, caKeyPEM := caPEMFor(t)
	signer, _, err := edgecp.NewProvidedSigner(caCertPEM, caKeyPEM, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	h := edgecp.NewServer(edgecp.NewCertStore(), edgecp.NewAuthz(nil)).WithSigner(signer).Handler()
	srv := httptest.NewTLSServer(h)
	defer srv.Close()

	// The httptest server cert is self-signed; use it as the mandatory CP server CA.
	serverCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	c, err := NewClient(srv.URL, serverCAPEM)
	if err != nil {
		t.Fatal(err)
	}
	b, unchanged, err := c.Fetch(0, false)
	if err != nil || unchanged {
		t.Fatalf("fetch: err=%v unchanged=%v", err, unchanged)
	}
	if b.CAID != signer.CAID() {
		t.Errorf("ca_id mismatch: %q vs %q", b.CAID, signer.CAID())
	}

	m := NewManager()
	if err := m.apply(b); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// An edge leaf the CA signs must verify against the applied pool.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chainPEM, _, _, err := signer.Sign(leafKey.Public(), "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(chainPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     m.ClientCAs(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("edge leaf does not verify against the pulled trust bundle: %v", err)
	}
}

// TestNewClientRequiresCA proves the mandatory-CA inversion: an empty/unparseable
// CP server CA is a hard error (no system-roots fallback).
func TestNewClientRequiresCA(t *testing.T) {
	if _, err := NewClient("https://cp:8443", nil); err == nil {
		t.Error("empty CA must be rejected (no system-roots fallback)")
	}
	if _, err := NewClient("https://cp:8443", []byte("not a cert")); err == nil {
		t.Error("unparseable CA must be rejected")
	}
}
