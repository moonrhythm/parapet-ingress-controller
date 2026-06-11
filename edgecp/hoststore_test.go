package edgecp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// The /v1/hosts endpoint scopes the known-host list to the token's allowed hosts.
func TestServerHostsEndpointScopes(t *testing.T) {
	store := NewHostsStore()
	store.SetHosts([]string{"acme.com", "evil.com", "app.acme.com"})

	authz := NewAuthz(map[string][]string{"tok": {"acme.com", "app.acme.com"}})
	h := NewServer(NewCertStore(), authz).WithHosts(store).Handler()

	req := httptest.NewRequest("GET", "/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var resp hostsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resp.Hosts, []string{"acme.com", "app.acme.com"}) {
		t.Errorf("hosts must exclude evil.com and be sorted: got %v", resp.Hosts)
	}

	// ETag present, and a matching If-None-Match 304s.
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}
	req2 := httptest.NewRequest("GET", "/v1/hosts", nil)
	req2.Header.Set("Authorization", "Bearer tok")
	req2.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("want 304 on matching ETag, got %d", rec2.Code)
	}
}

func TestServerHostsDisabled(t *testing.T) {
	authz := NewAuthz(map[string][]string{"tok": {"acme.com"}})
	h := NewServer(NewCertStore(), authz).Handler() // no WithHosts
	req := httptest.NewRequest("GET", "/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 when hosts disabled, got %d", rec.Code)
	}
}

// Identical content must not bump the generation (etag-stable across re-derives).
func TestHostsStoreGenerationStableOnIdenticalContent(t *testing.T) {
	s := NewHostsStore()
	s.SetHosts([]string{"a.com", "b.com"})
	gen := s.gen.Load()
	s.SetHosts([]string{"a.com", "b.com"})
	if s.gen.Load() != gen {
		t.Error("generation bumped on identical content")
	}
}
