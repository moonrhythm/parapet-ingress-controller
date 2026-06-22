package edgecp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestServerCorazaEndpointScopesBindings(t *testing.T) {
	store := NewCorazaStore()
	store.SetGlobal("SecRuleEngine On")
	store.SetZones(map[string]string{"cust1/z": "zone-rules", "cust2/other": "other-rules"})
	store.SetIngressDerived(map[string]string{"acme.com/api/": "cust1/z", "evil.com/": "cust2/other"})

	authz := NewAuthz(map[string][]string{"tok": {"acme.com"}})
	h := NewServer(NewCertStore(), authz).WithCoraza(store).Handler()

	req := httptest.NewRequest("GET", "/v1/coraza", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var resp corazaResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.GlobalRules != "SecRuleEngine On" {
		t.Errorf("global always included: got %q", resp.GlobalRules)
	}
	if !reflect.DeepEqual(resp.RouteZoneMap, map[string]string{"acme.com/api/": "cust1/z"}) {
		t.Errorf("route_zone_map must exclude evil.com: got %v", resp.RouteZoneMap)
	}
	if !reflect.DeepEqual(resp.Zones, map[string]string{"cust1/z": "zone-rules"}) {
		t.Errorf("zones must include only referenced+allowed: got %v", resp.Zones)
	}
}

func TestServerCorazaDisabled404(t *testing.T) {
	authz := NewAuthz(map[string][]string{"tok": {"acme.com"}})
	h := NewServer(NewCertStore(), authz).Handler() // no WithCoraza

	req := httptest.NewRequest("GET", "/v1/coraza", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 when distribution disabled, got %d", rec.Code)
	}
}

func TestCorazaEndpointETagRevalidates(t *testing.T) {
	store := NewCorazaStore()
	store.SetGlobal("SecRuleEngine On")

	authz := NewAuthz(map[string][]string{"tok": {"acme.com"}})
	h := NewServer(NewCertStore(), authz).WithCoraza(store).Handler()

	do := func(inm string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/v1/coraza", nil)
		req.Header.Set("Authorization", "Bearer tok")
		if inm != "" {
			req.Header.Set("If-None-Match", inm)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	first := do("")
	if first.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", first.Code)
	}
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}
	if again := do(etag); again.Code != http.StatusNotModified {
		t.Fatalf("want 304 on matching If-None-Match, got %d", again.Code)
	}
}

func TestConcatGlobalCorazaRulesDeterministicOrder(t *testing.T) {
	// Two global ConfigMaps in pod-ns, presented in DIFFERENT list orders, must
	// concatenate identically (sorted by namespace/name) — so two CP replicas
	// serving byte-identical content mint the same ETag and 304s hold. SecLang
	// rule execution order also depends on this.
	a := wafConfigMap{namespace: "ns", name: "a", labels: map[string]string{CorazaLabelKey: corazaRoleGlobal}, data: map[string]string{"r": "rule-a"}}
	b := wafConfigMap{namespace: "ns", name: "b", labels: map[string]string{CorazaLabelKey: corazaRoleGlobal}, data: map[string]string{"r": "rule-b"}}

	got1 := concatGlobalCorazaRules([]wafConfigMap{a, b}, "ns")
	got2 := concatGlobalCorazaRules([]wafConfigMap{b, a}, "ns")
	if got1 != got2 {
		t.Fatalf("order-dependent concatenation: %q vs %q", got1, got2)
	}
	if got1 != "rule-a\nrule-b" {
		t.Errorf("want namespace/name-sorted concat, got %q", got1)
	}
	// a global CM outside pod-ns is ignored
	c := wafConfigMap{namespace: "other", name: "a", labels: map[string]string{CorazaLabelKey: corazaRoleGlobal}, data: map[string]string{"r": "rule-c"}}
	if got := concatGlobalCorazaRules([]wafConfigMap{a, b, c}, "ns"); got != "rule-a\nrule-b" {
		t.Errorf("out-of-namespace global must be ignored, got %q", got)
	}
}

func TestCorazaStoreScopedConsistency(t *testing.T) {
	store := NewCorazaStore()
	store.SetGlobal("g")
	store.SetZones(map[string]string{"ns/a": "ra", "ns/b": "rb"})
	store.SetIngressDerived(map[string]string{"a.com/": "ns/a", "b.com/": "ns/b"})

	snap := store.scoped(func(host string) bool { return host == "a.com" })
	if snap.global != "g" {
		t.Errorf("global always included")
	}
	if !reflect.DeepEqual(snap.routeZone, map[string]string{"a.com/": "ns/a"}) {
		t.Errorf("routeZone scoped wrong: %v", snap.routeZone)
	}
	if !reflect.DeepEqual(snap.zones, map[string]string{"ns/a": "ra"}) {
		t.Errorf("zones scoped wrong: %v", snap.zones)
	}
}
