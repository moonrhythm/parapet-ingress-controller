package edgecp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The WAF/ratelimit generation is a PROCESS-LOCAL counter: two CP replicas
// serving byte-identical content sit at different generations (different boot
// times / reload counts). The ETag must therefore be computed over the content
// WITHOUT the generation — otherwise an edge whose polls rotate across replicas
// (IdleConnTimeout redials every poll) never gets a 304 and re-downloads +
// recompiles the full bundle forever.

func TestWafEtagExcludesProcessLocalGeneration(t *testing.T) {
	store := NewWafStore()
	store.SetGlobal("rules-a") // generation 1
	srv := NewServer(NewCertStore(), NewAuthz(map[string][]string{"tok": {"example.com"}})).WithWAF(store)
	h := srv.Handler()

	get := func(ifNoneMatch string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/v1/waf", nil)
		req.Header.Set("Authorization", "Bearer tok")
		if ifNoneMatch != "" {
			req.Header.Set("If-None-Match", ifNoneMatch)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	first := get("")
	if first.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", first.Code)
	}
	etag1 := first.Header().Get("ETag")
	if etag1 == "" {
		t.Fatal("no ETag on 200")
	}

	// Same content at a higher generation (simulates another replica, or an
	// edit cycled back): identical validator, and revalidation 304s.
	store.SetGlobal("rules-b") // generation 2
	store.SetGlobal("rules-a") // generation 3, content identical to generation 1
	second := get("")
	if got := second.Header().Get("ETag"); got != etag1 {
		t.Fatalf("ETag changed with content identical: %s -> %s (generation leaked into the validator)", etag1, got)
	}
	var resp wafResponse
	if err := json.Unmarshal(second.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Generation != 3 {
		t.Fatalf("generation = %d, want 3 (the REAL generation must still ride the body)", resp.Generation)
	}
	if rec := get(etag1); rec.Code != http.StatusNotModified {
		t.Fatalf("revalidation status = %d, want 304", rec.Code)
	}

	// A real content change must still bust the validator.
	store.SetGlobal("rules-c")
	if rec := get(etag1); rec.Code != http.StatusOK {
		t.Fatalf("changed content with stale validator: status = %d, want 200", rec.Code)
	}
}

func TestRateLimitEtagExcludesProcessLocalGeneration(t *testing.T) {
	store := NewRateLimitStore()
	store.SetGlobal([]string{"limits-a"}) // generation 1
	srv := NewServer(NewCertStore(), NewAuthz(map[string][]string{"tok": {"example.com"}})).WithRateLimit(store)
	h := srv.Handler()

	get := func(ifNoneMatch string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/v1/ratelimit", nil)
		req.Header.Set("Authorization", "Bearer tok")
		if ifNoneMatch != "" {
			req.Header.Set("If-None-Match", ifNoneMatch)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	first := get("")
	if first.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", first.Code)
	}
	etag1 := first.Header().Get("ETag")

	store.SetGlobal([]string{"limits-b"}) // generation 2
	store.SetGlobal([]string{"limits-a"}) // generation 3, content identical
	if got := get("").Header().Get("ETag"); got != etag1 {
		t.Fatalf("ETag changed with content identical: %s -> %s (generation leaked into the validator)", etag1, got)
	}
	if rec := get(etag1); rec.Code != http.StatusNotModified {
		t.Fatalf("revalidation status = %d, want 304", rec.Code)
	}
}
