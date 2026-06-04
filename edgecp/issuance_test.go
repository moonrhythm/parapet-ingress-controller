package edgecp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// testEdgeCA returns a dedicated, single-purpose edge CA: IsCA, KeyUsageCertSign,
// EKU clientAuth, NameConstrained to the SPIFFE trust domain — exactly what managed
// mode would generate. Returns (certPEM, keyPEM).
func testEdgeCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "parapet-edge-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		PermittedURIDomains:   []string{SANTrustDomain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func testCSR(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	// A "hint" SAN the CP must ignore (it stamps the token-derived SAN instead).
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		URIs: []*url.URL{{Scheme: "spiffe", Host: "evil.example", Path: "/edge/attacker"}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestSignerIssuesVerifiableLeaf(t *testing.T) {
	certPEM, keyPEM := testEdgeCA(t)
	sg, warnings, err := NewProvidedSigner(certPEM, keyPEM, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("a name-constrained clientAuth CA should warn nothing, got %v", warnings)
	}

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chainPEM, notAfter, serial, err := sg.Sign(leafKey.Public(), "acme-edge-1")
	if err != nil {
		t.Fatal(err)
	}
	if serial == "" || notAfter.Before(time.Now()) {
		t.Errorf("bad serial/notAfter: %q %v", serial, notAfter)
	}

	// The chain must verify against the CA bundle (this IS the core's trust predicate).
	leaf, intermediates := parseChain(t, chainPEM)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(sg.BundlePEM()) {
		t.Fatal("append CA bundle")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify to the edge CA: %v", err)
	}

	// The CP-stamped SAN, not the CSR hint; leaf shape per the self-check.
	if got := leaf.URIs[0].String(); got != "spiffe://parapet.moonrhythm.io/edge/acme-edge-1" {
		t.Errorf("SAN = %q, want the token-derived edge SAN", got)
	}
	if leaf.IsCA || len(leaf.DNSNames) != 0 {
		t.Error("leaf must not be a CA and must carry no DNS SANs")
	}
}

func TestSignerRejectsRSALeafKey(t *testing.T) {
	certPEM, keyPEM := testEdgeCA(t)
	sg, _, err := NewProvidedSigner(certPEM, keyPEM, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, _, _, err := sg.Sign(rsaKey.Public(), "x"); err == nil {
		t.Error("RSA leaf key must be rejected by the key whitelist")
	}
}

func TestEdgeCertEndpoint(t *testing.T) {
	certPEM, keyPEM := testEdgeCA(t)
	sg, _, _ := NewProvidedSigner(certPEM, keyPEM, time.Hour, time.Minute)
	authz := NewAuthzEntries(map[string]Entry{
		"tok-ok":       {ID: "acme-edge-1", Domains: []string{"acme.com"}},
		"tok-no-id":    {Domains: []string{"acme.com"}}, // may fetch certs, but no data-plane identity
		"tok-disabled": {ID: "ghost", Domains: []string{"acme.com"}, Disabled: true},
	})
	h := NewServer(NewCertStore(), authz).WithSigner(sg, 1).Handler()

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := testCSR(t, leafKey)

	post := func(token string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(edgeCertRequest{CSRPEM: string(csr)})
		req := httptest.NewRequest("POST", "/v1/edge-cert", strings.NewReader(string(body)))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := post("tok-ok"); rec.Code != http.StatusOK {
		t.Fatalf("happy path: want 200, got %d (%s)", rec.Code, rec.Body)
	} else {
		var resp edgeCertResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(resp.ChainPEM, "CERTIFICATE") || resp.Serial == "" {
			t.Error("missing chain/serial")
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Error("issued cert must be no-store")
		}
	}
	if rec := post(""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: want 401, got %d", rec.Code)
	}
	if rec := post("tok-disabled"); rec.Code != http.StatusUnauthorized {
		t.Errorf("disabled token: want 401 (locked out), got %d", rec.Code)
	}
	if rec := post("tok-no-id"); rec.Code != http.StatusForbidden {
		t.Errorf("no id grant: want 403, got %d", rec.Code)
	}

	// Absent signer ⇒ 404.
	hNoSigner := NewServer(NewCertStore(), authz).Handler()
	body, _ := json.Marshal(edgeCertRequest{CSRPEM: string(csr)})
	req := httptest.NewRequest("POST", "/v1/edge-cert", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer tok-ok")
	rec := httptest.NewRecorder()
	hNoSigner.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("absent signer: want 404, got %d", rec.Code)
	}
}

func TestTrustBundleEndpoint(t *testing.T) {
	certPEM, keyPEM := testEdgeCA(t)
	sg, _, _ := NewProvidedSigner(certPEM, keyPEM, time.Hour, time.Minute)
	srv := NewServer(NewCertStore(), NewAuthz(nil))

	// Absent signer ⇒ 503.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/v1/trust-bundle", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no signer: want 503, got %d", rec.Code)
	}

	srv.SetSigner(sg, 1)
	h := srv.Handler()

	// Tokenless 200 with {generation, ca_pem, ca_id}.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/trust-bundle", nil)) // no Authorization header
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var resp trustBundleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Generation == 0 || !strings.Contains(resp.CAPEM, "CERTIFICATE") || resp.CAID == "" {
		t.Errorf("bad bundle: %+v", resp)
	}
	if strings.Contains(resp.CAPEM, "PRIVATE KEY") {
		t.Fatal("ca_pem must never contain a private key")
	}
	if resp.CAID != sg.CAID() {
		t.Errorf("ca_id = %q, want %q", resp.CAID, sg.CAID())
	}

	// 304 on a matching If-None-Match.
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}
	req := httptest.NewRequest("GET", "/v1/trust-bundle", nil)
	req.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusNotModified {
		t.Errorf("want 304, got %d", rec2.Code)
	}
}

func TestAuthzDisabledFullLockout(t *testing.T) {
	a := NewAuthzEntries(map[string]Entry{
		"live": {ID: "e1", Domains: []string{"acme.com"}},
		"dead": {ID: "e2", Domains: []string{"acme.com"}, Disabled: true},
	})
	// A disabled token is UNKNOWN everywhere — no Known, no Allowed (cert/WAF), no Identity.
	if a.Known("dead") {
		t.Error("disabled token must not be Known")
	}
	if a.Allowed("dead", "acme.com") {
		t.Error("disabled token must not be Allowed any domain (no /v1/certs, /v1/waf)")
	}
	if _, ok := a.Identity("dead"); ok {
		t.Error("disabled token must have no Identity (no /v1/edge-cert)")
	}
	// The live token works, and a token without an id has no Identity.
	if id, ok := a.Identity("live"); !ok || id != "e1" {
		t.Errorf("live Identity = %q,%v", id, ok)
	}
}

func parseChain(t *testing.T, chainPEM []byte) (leaf *x509.Certificate, intermediates *x509.CertPool) {
	t.Helper()
	intermediates = x509.NewCertPool()
	rest := chainPEM
	first := true
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if first {
			leaf = c
			first = false
		} else {
			intermediates.AddCert(c)
		}
	}
	if leaf == nil {
		t.Fatal("no leaf in chain")
	}
	return leaf, intermediates
}
