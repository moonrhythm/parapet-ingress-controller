package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
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

// fpOfPEM returns the SHA-256 (hex) of a single cert PEM's DER — the same value the CP and
// deriveIssuerFP compute.
func fpOfPEM(t *testing.T, certPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// chainDERs splits a leaf-first chain PEM into its CERTIFICATE DER blocks (leaf, then CAs).
func chainDERs(t *testing.T, chainPEM []byte) [][]byte {
	t.Helper()
	var ders [][]byte
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			ders = append(ders, block.Bytes)
		}
	}
	return ders
}

// deriveIssuerFP must resolve WHICH CA in the chain signed the leaf (the load-bearing
// active=OLD-vs-NEW signal), matching on AuthorityKeyId==SubjectKeyId, and FAIL CLOSED ("")
// on no/ambiguous match — a wrong answer would false-green an OLD-signed leaf at the drop.
func TestDeriveIssuerFP(t *testing.T) {
	// Two real edge CAs (edgecp.GenerateCA stamps an explicit SubjectKeyId, so a leaf's
	// AuthorityKeyId equals its signer's SubjectKeyId — the anchor we match on).
	oldCert, oldKey, err := edgecp.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCert, newKey, err := edgecp.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldFP, newFP := fpOfPEM(t, oldCert), fpOfPEM(t, newCert)
	bundle := append(append([]byte(nil), oldCert...), newCert...)

	mint := func(keyPEM []byte, activeFP string) (*x509.Certificate, [][]byte) {
		sg, _, err := edgecp.NewProvidedSignerActive(bundle, keyPEM, activeFP, time.Hour, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		chainPEM, _, _, err := sg.Sign(k.Public(), "edge-x")
		if err != nil {
			t.Fatal(err)
		}
		ders := chainDERs(t, chainPEM)
		leaf, err := x509.ParseCertificate(ders[0])
		if err != nil {
			t.Fatal(err)
		}
		return leaf, ders
	}

	// NEW-signed leaf over the OLD++NEW chain → the NEW CA's fp.
	newLeaf, newChain := mint(newKey, newFP)
	if got := deriveIssuerFP(newLeaf, newChain); got != newFP {
		t.Errorf("NEW-signed leaf: deriveIssuerFP = %s, want NEW %s", got, newFP)
	}
	// OLD-signed leaf → the OLD CA's fp (proves it discriminates, not first-match).
	oldLeaf, oldChain := mint(oldKey, oldFP)
	if got := deriveIssuerFP(oldLeaf, oldChain); got != oldFP {
		t.Errorf("OLD-signed leaf: deriveIssuerFP = %s, want OLD %s", got, oldFP)
	}

	// Ambiguous: the signing CA appears TWICE in the chain → two SKID matches → "".
	caDER := newChain[len(newChain)-1] // the NEW CA block
	ambiguous := [][]byte{newChain[0], caDER, caDER}
	if got := deriveIssuerFP(newLeaf, ambiguous); got != "" {
		t.Errorf("ambiguous (duplicate signer): want \"\", got %s", got)
	}
	// No match: only an unrelated CA in the chain → "" (neither SKID nor signature matches).
	otherCert, _, err := edgecp.GenerateCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	otherDER := chainDERs(t, otherCert)[0]
	if got := deriveIssuerFP(newLeaf, [][]byte{newChain[0], otherDER}); got != "" {
		t.Errorf("no matching CA: want \"\", got %s", got)
	}
	// Too short (no CA block) → "".
	if got := deriveIssuerFP(newLeaf, [][]byte{newChain[0]}); got != "" {
		t.Errorf("chain with no CA: want \"\", got %s", got)
	}
	if got := deriveIssuerFP(nil, newChain); got != "" {
		t.Errorf("nil leaf: want \"\", got %s", got)
	}
}
