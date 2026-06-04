package edgecp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// handleCert must emit X-Parapet-CA-Id on the 404 (no cert), the 304 (revalidate), AND
// the 200 — the universal force-re-mint signal that rides the edge's existing poll.
func TestHandleCertEmitsCAIDOnEveryArm(t *testing.T) {
	certPEM, keyPEM := testEdgeCA(t)
	signer, _, err := NewProvidedSigner(certPEM, keyPEM, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store := NewCertStore()
	srv := NewServer(store, NewAuthz(map[string][]string{"tok": {"acme.com"}})).WithSigner(signer, 1)
	want := signer.CAID()
	h := srv.Handler()

	get := func(inm string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/v1/certs?sni=acme.com", nil)
		req.Header.Set("Authorization", "Bearer tok")
		if inm != "" {
			req.Header.Set("If-None-Match", inm)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 404: authorized sni, no cert in the store yet.
	rec := get("")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Parapet-CA-Id"); got != want {
		t.Errorf("404 X-Parapet-CA-Id = %q, want %q", got, want)
	}

	// 200: load the cert.
	store.Set([]PEMPair{mkPair(t, "acme.com")})
	rec = get("")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Parapet-CA-Id"); got != want {
		t.Errorf("200 X-Parapet-CA-Id = %q, want %q", got, want)
	}
	etag := rec.Header().Get("ETag")

	// 304: the SIGNAL must ride the revalidation (steady state is ~all 304s).
	rec = get(etag)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("want 304, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Parapet-CA-Id"); got != want {
		t.Errorf("304 X-Parapet-CA-Id = %q, want %q (the load-bearing steady-state carrier)", got, want)
	}
}

// An unauthorized caller must NOT learn the signer state (no header on 401/403).
func TestHandleCertNoCAIDForUnauthorized(t *testing.T) {
	certPEM, keyPEM := testEdgeCA(t)
	signer, _, _ := NewProvidedSigner(certPEM, keyPEM, time.Hour, time.Minute)
	srv := NewServer(NewCertStore(), NewAuthz(map[string][]string{"tok": {"acme.com"}})).WithSigner(signer, 1)
	h := srv.Handler()

	// 401 (no token).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/certs?sni=acme.com", nil))
	if rec.Header().Get("X-Parapet-CA-Id") != "" {
		t.Error("401 must not leak the CA-Id")
	}
	// 403 (token not allowed for this sni).
	req := httptest.NewRequest("GET", "/v1/certs?sni=other.com", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("X-Parapet-CA-Id") != "" {
		t.Error("403 must not leak the CA-Id")
	}
}

// The edge-cert response carries ca_id; the saturation gate sheds with 503+Retry-After.
func TestEdgeCertCAIDAndSaturation(t *testing.T) {
	certPEM, keyPEM := testEdgeCA(t)
	signer, _, _ := NewProvidedSigner(certPEM, keyPEM, time.Hour, time.Minute)
	authz := NewAuthzEntries(map[string]Entry{"tok": {ID: "edge-1", Domains: []string{"acme.com"}}})
	srv := NewServer(NewCertStore(), authz).WithSigner(signer, 1).WithSignConcurrency(1, 9)
	h := srv.Handler()

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := testCSR(t, leafKey)
	post := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(edgeCertRequest{CSRPEM: string(csr)})
		req := httptest.NewRequest("POST", "/v1/edge-cert", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Happy path: 200 with ca_id == the signer's.
	rec := post()
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body)
	}
	var resp edgeCertResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.CAID != signer.CAID() {
		t.Errorf("response ca_id = %q, want %q", resp.CAID, signer.CAID())
	}

	// Saturate the single signing slot → the next request sheds 503 + Retry-After.
	srv.signGate <- struct{}{}
	rec = post()
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("saturated: want 503, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "9" {
		t.Errorf("Retry-After = %q, want 9", rec.Header().Get("Retry-After"))
	}
	<-srv.signGate
}
