package edgecp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// This exercises the full HTTP wire contract a real edge client depends on:
// the server (NewServer.Handler) behind a real httptest server, driven by a real
// net/http client doing exactly what the Rust CpClient does — GET
// /v1/certs/{sni} with a bearer token and If-None-Match. It guards the contract
// in EDGE.md so an accidental change to status codes / headers / JSON shape is
// caught here.

func mkPair(t *testing.T, sans ...string) PEMPair {
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
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return PEMPair{
		ChainPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

func TestIntegrationCertFetchOverHTTP(t *testing.T) {
	store := NewCertStore()
	store.Set([]PEMPair{mkPair(t, "acme.com", "www.acme.com")})
	authz := NewAuthz(map[string][]string{"edge-eu": {"acme.com", "*.acme.com"}})

	srv := httptest.NewServer(NewServer(store, authz).Handler())
	defer srv.Close()
	client := srv.Client()

	get := func(sni, token, inm string) *http.Response {
		req, err := http.NewRequest("GET", srv.URL+"/v1/certs/"+sni, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if inm != "" {
			req.Header.Set("If-None-Match", inm)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// 200: returns cert+key JSON and an ETag; key must not be cacheable.
	resp := get("acme.com", "edge-eu", "")
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Error("missing ETag")
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("private key response must be no-store, got %q", cc)
	}
	var body certResponse
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.ChainPEM == "" || body.KeyPEM == "" {
		t.Error("empty cert material in body")
	}

	// wildcard SNI the token is allowed for, resolved by the store's wildcard climb
	if r := get("www.acme.com", "edge-eu", ""); r.StatusCode != 200 {
		t.Errorf("wildcard sni: want 200, got %d", r.StatusCode)
	} else {
		r.Body.Close()
	}

	// 304 when the edge presents the current ETag
	if r := get("acme.com", "edge-eu", etag); r.StatusCode != 304 {
		t.Errorf("revalidation: want 304, got %d", r.StatusCode)
	} else {
		r.Body.Close()
	}

	// 403 for a domain outside the token's allow-set (even if a cert existed)
	if r := get("acme.com", "other-token-shaped", ""); r.StatusCode != 401 {
		// unknown token -> 401 (not 403): the token itself isn't recognized
		t.Errorf("unknown token: want 401, got %d", r.StatusCode)
	} else {
		r.Body.Close()
	}

	// 403: known token, domain not allowed
	authz2 := NewAuthz(map[string][]string{"edge-eu": {"acme.com"}})
	srv2 := httptest.NewServer(NewServer(store, authz2).Handler())
	defer srv2.Close()
	req, _ := http.NewRequest("GET", srv2.URL+"/v1/certs/notmine.com", nil)
	req.Header.Set("Authorization", "Bearer edge-eu")
	r, err := srv2.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 403 {
		t.Errorf("disallowed domain: want 403, got %d", r.StatusCode)
	}
	r.Body.Close()

	// 401 without a token
	if r := get("acme.com", "", ""); r.StatusCode != 401 {
		t.Errorf("no token: want 401, got %d", r.StatusCode)
	} else {
		r.Body.Close()
	}
}
