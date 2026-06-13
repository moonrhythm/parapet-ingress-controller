package edgecp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestCollectCacheDocs(t *testing.T) {
	cms := []wafConfigMap{
		{namespace: "platform", name: "b-global", labels: map[string]string{CacheLabelKey: "global"},
			data: map[string]string{"z.yaml": "doc-b2", "a.yaml": "doc-b1"}},
		{namespace: "platform", name: "a-global", labels: map[string]string{CacheLabelKey: "global"},
			data: map[string]string{"l.yaml": "doc-a"}},
		// global outside podNamespace is a tenant injection attempt — ignored
		{namespace: "cust1", name: "evil-global", labels: map[string]string{CacheLabelKey: "global"},
			data: map[string]string{"x": "evil"}},
		{namespace: "cust1", name: "basic", labels: map[string]string{CacheLabelKey: "zone"},
			data: map[string]string{"l.yaml": "zone-doc"}},
	}

	global := collectGlobalCacheDocs(cms, "platform")
	want := []string{"doc-a", "doc-b1", "doc-b2"} // by namespace/name, then data key
	if !reflect.DeepEqual(global, want) {
		t.Errorf("global docs: got %v, want %v", global, want)
	}

	zones := collectZoneCacheDocs(cms)
	if !reflect.DeepEqual(zones, map[string][]string{"cust1/basic": {"zone-doc"}}) {
		t.Errorf("zone docs: got %v", zones)
	}
}

func TestCacheStoreScopedAndGeneration(t *testing.T) {
	s := NewCacheStore()
	gen0 := s.gen.Load()
	s.SetGlobal([]string{"gdoc"})
	s.SetZones(map[string][]string{"cust1/basic": {"zdoc"}, "cust2/other": {"odoc"}})
	s.SetIngressDerived(map[string]string{
		"a.example.com/api/": "cust1/basic",
		"d.example.com/":     "cust2/other",
	})
	if s.gen.Load() == gen0 {
		t.Fatal("generation should bump on content change")
	}

	// scope to an edge allowed everything except d.example.com
	snap := s.scoped(func(host string) bool { return host != "d.example.com" })
	if !reflect.DeepEqual(snap.global, []string{"gdoc"}) {
		t.Errorf("global always included: got %v", snap.global)
	}
	if !reflect.DeepEqual(snap.routeZone, map[string]string{"a.example.com/api/": "cust1/basic"}) {
		t.Errorf("routeZone not scoped by pattern host: got %v", snap.routeZone)
	}
	if !reflect.DeepEqual(snap.zones, map[string][]string{"cust1/basic": {"zdoc"}}) {
		t.Errorf("zones must include only referenced+allowed: got %v", snap.zones)
	}

	// unchanged content must not bump the generation (etag stability)
	gen := s.gen.Load()
	s.SetGlobal([]string{"gdoc"})
	if s.gen.Load() != gen {
		t.Error("generation bumped on identical content")
	}
}

func TestServerCacheEndpoint(t *testing.T) {
	store := NewCacheStore()
	store.SetGlobal([]string{"gdoc"})
	store.SetZones(map[string][]string{"cust1/basic": {"zdoc"}})
	store.SetIngressDerived(map[string]string{
		"acme.com/": "cust1/basic",
		"evil.com/": "cust1/basic",
	})

	authz := NewAuthz(map[string][]string{"tok": {"acme.com"}})
	h := NewServer(NewCertStore(), authz).WithCache(store).Handler()

	// happy path, scoped to the token's domains
	req := httptest.NewRequest("GET", "/v1/cache", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var resp cacheResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resp.GlobalOverrides, []string{"gdoc"}) {
		t.Errorf("global: got %v", resp.GlobalOverrides)
	}
	if !reflect.DeepEqual(resp.RouteZoneMap, map[string]string{"acme.com/": "cust1/basic"}) {
		t.Errorf("route_zone_map must exclude evil.com: got %v", resp.RouteZoneMap)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}

	// 304 on matching If-None-Match
	req2 := httptest.NewRequest("GET", "/v1/cache", nil)
	req2.Header.Set("Authorization", "Bearer tok")
	req2.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotModified {
		t.Errorf("want 304, got %d", rec2.Code)
	}

	// 401 without a token
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, httptest.NewRequest("GET", "/v1/cache", nil))
	if rec3.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rec3.Code)
	}

	// 404 when distribution is disabled (no WithCache)
	h2 := NewServer(NewCertStore(), authz).Handler()
	rec4 := httptest.NewRecorder()
	req4 := httptest.NewRequest("GET", "/v1/cache", nil)
	req4.Header.Set("Authorization", "Bearer tok")
	h2.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec4.Code)
	}
}
