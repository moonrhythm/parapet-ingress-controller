package edgecp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// The /v1/topology endpoint scopes every binding map and the known-host list to
// the token's allowed hosts — the per-edge isolation that used to live on the
// WAF and rate-limit endpoints.
func TestServerTopologyEndpointScopesBindings(t *testing.T) {
	store := NewTopologyStore()
	store.SetIngressDerived(
		map[string]string{"acme.com": "cust1/waf", "evil.com": "cust2/waf"},       // wafHostZone
		map[string]string{"acme.com/api/": "cust1/waf", "evil.com/": "cust2/waf"}, // wafRouteZone
		map[string]string{"acme.com": "cust1/rl", "evil.com": "cust2/rl"},         // rlHostZone
		map[string]string{"acme.com/": "cust1/rl", "evil.com/": "cust2/rl"},       // rlRouteZone
		[]string{"acme.com", "evil.com"},                                          // hosts
	)

	authz := NewAuthz(map[string][]string{"tok": {"acme.com"}})
	h := NewServer(NewCertStore(), authz).WithTopology(store).Handler()

	req := httptest.NewRequest("GET", "/v1/topology", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var resp topologyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resp.WAFRouteZone, map[string]string{"acme.com/api/": "cust1/waf"}) {
		t.Errorf("waf_route_zone must exclude evil.com: got %v", resp.WAFRouteZone)
	}
	if !reflect.DeepEqual(resp.WAFHostZone, map[string]string{"acme.com": "cust1/waf"}) {
		t.Errorf("waf_host_zone must exclude evil.com: got %v", resp.WAFHostZone)
	}
	if !reflect.DeepEqual(resp.RLRouteZone, map[string]string{"acme.com/": "cust1/rl"}) {
		t.Errorf("rl_route_zone must exclude evil.com: got %v", resp.RLRouteZone)
	}
	if !reflect.DeepEqual(resp.RLHostZone, map[string]string{"acme.com": "cust1/rl"}) {
		t.Errorf("rl_host_zone must exclude evil.com: got %v", resp.RLHostZone)
	}
	if !reflect.DeepEqual(resp.Hosts, []string{"acme.com"}) {
		t.Errorf("hosts must be scoped: got %v", resp.Hosts)
	}

	// ETag present, and an If-None-Match match 304s.
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}
	req2 := httptest.NewRequest("GET", "/v1/topology", nil)
	req2.Header.Set("Authorization", "Bearer tok")
	req2.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("want 304 on matching ETag, got %d", rec2.Code)
	}
}

// A disabled topology store 404s (no skew fallback — the edge handles it fail-static).
func TestServerTopologyDisabled(t *testing.T) {
	authz := NewAuthz(map[string][]string{"tok": {"acme.com"}})
	h := NewServer(NewCertStore(), authz).Handler() // no WithTopology
	req := httptest.NewRequest("GET", "/v1/topology", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 when topology disabled, got %d", rec.Code)
	}
}
