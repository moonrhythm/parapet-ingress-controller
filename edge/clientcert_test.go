package edge

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

func testCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "parapet-edge-ca"},
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

// TestEdgeCertIssuanceEndToEnd runs a real control-plane handler in httptest, has
// the edge fetch a data-plane client cert through the Cp client, and asserts the
// installed leaf verifies to the edge CA — i.e. the core's CA-only trust predicate
// would accept it.
func TestEdgeCertIssuanceEndToEnd(t *testing.T) {
	caCertPEM, caKeyPEM := testCA(t)
	signer, _, err := edgecp.NewProvidedSigner(caCertPEM, caKeyPEM, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authz := edgecp.NewAuthzEntries(map[string]edgecp.Entry{
		"tok": {ID: "acme-edge-1", Domains: []string{"acme.com"}},
	})
	h := edgecp.NewServer(edgecp.NewCertStore(), authz).WithSigner(signer, 1).Handler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	cp, err := NewCpClient(srv.URL, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	store := NewClientCertStore()
	RefreshEdgeCertOnce(cp, store, "timer")

	if !store.Loaded() {
		t.Fatal("client cert not loaded after issuance")
	}
	cert, _ := store.GetClientCertificate(nil)
	if len(cert.Certificate) == 0 {
		t.Fatal("empty client cert")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(signer.BundlePEM()) {
		t.Fatal("append CA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("issued leaf does not verify to the edge CA: %v", err)
	}
	if leaf.URIs[0].String() != "spiffe://parapet.moonrhythm.io/edge/acme-edge-1" {
		t.Errorf("unexpected SAN %q", leaf.URIs[0])
	}
}

func TestClientCertStoreAllOrNothing(t *testing.T) {
	s := NewClientCertStore()

	// Empty cert before any load — present no client cert, never error the handshake.
	if c, err := s.GetClientCertificate(nil); err != nil || len(c.Certificate) != 0 {
		t.Errorf("pre-load: want empty cert no error, got %v %v", c, err)
	}
	if s.Loaded() {
		t.Error("should not be loaded")
	}

	// A bad chain is rejected and keeps the prior (nil) state.
	if err := s.Update([]byte("not a pem"), []byte("nope")); err == nil {
		t.Error("bad pair should error")
	}
	if s.Loaded() {
		t.Error("a failed Update must not mark loaded")
	}
}
