package edgecp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// The WAF endpoint scopes the zone RULESETS to the zones the token's allowed
// hosts bind to (the store still keeps its own copy of the bindings to do this).
// The bindings themselves now ship from /v1/topology — see
// TestServerTopologyEndpointScopesBindings.
func TestServerWAFEndpointScopesZones(t *testing.T) {
	store := NewWafStore()
	store.SetGlobal("global-rules")
	store.SetZones(map[string]string{"cust1/z": "zone-rules", "cust2/other": "other-rules"})
	store.SetIngressDerived(
		map[string]string{"acme.com": "cust1/z", "evil.com": "cust2/other"},
		map[string]string{"acme.com/api/": "cust1/z", "evil.com/": "cust2/other"},
	)

	authz := NewAuthz(map[string][]string{"tok": {"acme.com"}})
	h := NewServer(NewCertStore(), authz).WithWAF(store).Handler()

	req := httptest.NewRequest("GET", "/v1/waf", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var resp wafResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.GlobalRules != "global-rules" {
		t.Errorf("global always included: got %q", resp.GlobalRules)
	}
	if !reflect.DeepEqual(resp.Zones, map[string]string{"cust1/z": "zone-rules"}) {
		t.Errorf("zones must include only referenced+allowed: got %v", resp.Zones)
	}
}
