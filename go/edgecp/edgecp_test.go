package edgecp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// selfSigned returns a fullchain PEM + key PEM for the given SANs.
func selfSigned(t *testing.T, sans ...string) PEMPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: sans[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     sans,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return PEMPair{
		ChainPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

func TestCertStoreSNIMatch(t *testing.T) {
	s := NewCertStore()
	s.Set([]PEMPair{
		selfSigned(t, "acme.com"),
		selfSigned(t, "*.acme.com"),
	})

	if _, ok := s.Get("acme.com"); !ok {
		t.Error("exact match failed")
	}
	if _, ok := s.Get("www.acme.com"); !ok {
		t.Error("wildcard match failed")
	}
	if _, ok := s.Get("ACME.com."); !ok {
		t.Error("case+trailing-dot normalization failed")
	}
	if _, ok := s.Get("a.b.acme.com"); ok {
		t.Error("wildcard should match only one label")
	}
	if _, ok := s.Get("other.com"); ok {
		t.Error("unexpected match")
	}
}

func TestAuthz(t *testing.T) {
	a := NewAuthz(map[string][]string{
		"tok-eu":  {"acme.com", "*.acme.com"},
		"tok-all": {"*"},
	})
	if !a.Allowed("tok-eu", "acme.com") {
		t.Error("exact allow failed")
	}
	if !a.Allowed("tok-eu", "www.acme.com") {
		t.Error("wildcard allow failed")
	}
	if a.Allowed("tok-eu", "evil.com") {
		t.Error("should deny unlisted domain")
	}
	if a.Allowed("unknown", "acme.com") {
		t.Error("should deny unknown token")
	}
	// A bare "*" is the serve-all catch-all: any non-empty host, including
	// an apex, a deep subdomain, and a domain no other token lists.
	if !a.Allowed("tok-all", "acme.com") {
		t.Error("catch-all should allow apex")
	}
	if !a.Allowed("tok-all", "a.b.evil.com") {
		t.Error("catch-all should allow deep subdomain")
	}
	if a.Allowed("tok-all", "") {
		t.Error("catch-all should still deny empty host")
	}
	if !a.Known("tok-eu") || a.Known("nope") {
		t.Error("Known() wrong")
	}
}

func TestServerCertEndpoint(t *testing.T) {
	store := NewCertStore()
	pair := selfSigned(t, "acme.com")
	store.Set([]PEMPair{pair})
	authz := NewAuthz(map[string][]string{"tok": {"acme.com"}})
	h := NewServer(store, authz).Handler()

	// happy path
	req := httptest.NewRequest("GET", "/v1/certs?sni=acme.com", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var resp certResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ChainPEM == "" || resp.KeyPEM == "" {
		t.Error("empty cert material")
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Error("missing ETag")
	}

	// 304 on matching If-None-Match
	req2 := httptest.NewRequest("GET", "/v1/certs?sni=acme.com", nil)
	req2.Header.Set("Authorization", "Bearer tok")
	req2.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotModified {
		t.Errorf("want 304, got %d", rec2.Code)
	}

	// 403 for a domain the token isn't allowed (even though no such cert exists)
	req3 := httptest.NewRequest("GET", "/v1/certs?sni=evil.com", nil)
	req3.Header.Set("Authorization", "Bearer tok")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec3.Code)
	}

	// 401 without a token
	req4 := httptest.NewRequest("GET", "/v1/certs?sni=acme.com", nil)
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rec4.Code)
	}
}

func TestServerMissingSNI(t *testing.T) {
	store := NewCertStore()
	store.Set([]PEMPair{selfSigned(t, "acme.com")})
	authz := NewAuthz(map[string][]string{"tok": {"acme.com"}})
	h := NewServer(store, authz).Handler()

	// GET /v1/certs with no sni query param → 400 (even with a valid token).
	req := httptest.NewRequest("GET", "/v1/certs", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing sni: want 400, got %d", rec.Code)
	}

	// The old path-style URL no longer routes to the cert handler → 404.
	req2 := httptest.NewRequest("GET", "/v1/certs/acme.com", nil)
	req2.Header.Set("Authorization", "Bearer tok")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("old path-style: want 404, got %d", rec2.Code)
	}
}

func TestServerHealthzReadiness(t *testing.T) {
	store := NewCertStore() // not loaded yet
	authz := NewAuthz(map[string][]string{"tok": {"acme.com"}})
	h := NewServer(store, authz).Handler()

	// Liveness is always 200 while the process is up, even before a load.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("liveness: want 200, got %d", rec.Code)
	}

	// Readiness is 503 until the cert store has loaded at least once.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz?ready=1", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readiness before load: want 503, got %d", rec.Code)
	}

	// After a load (even an empty one — the cluster list succeeded), ready → 200.
	store.Set(nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz?ready=1", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("readiness after load: want 200, got %d", rec.Code)
	}
}
