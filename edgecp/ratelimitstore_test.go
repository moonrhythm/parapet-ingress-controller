package edgecp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func rlIngress(ns, name string, anns map[string]string, hosts ...string) networking.Ingress {
	rules := make([]networking.IngressRule, 0, len(hosts))
	for _, h := range hosts {
		rules = append(rules, networking.IngressRule{Host: h})
	}
	return networking.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: anns},
		Spec:       networking.IngressSpec{Rules: rules},
	}
}

func TestBuildRateLimitHostZone(t *testing.T) {
	ings := []networking.Ingress{
		// bare id resolves to the ingress's own namespace
		rlIngress("cust1", "app", map[string]string{RateLimitZoneAnnotation: "basic"}, "A.example.com", "b.example.com"),
		// "ns/id" naming the OWN namespace is honored
		rlIngress("cust2", "app", map[string]string{RateLimitZoneAnnotation: "cust2/basic"}, "c.example.com"),
		// cross-namespace reference is ignored (shared counter state)
		rlIngress("cust3", "app", map[string]string{RateLimitZoneAnnotation: "cust1/basic"}, "d.example.com"),
		// no annotation contributes nothing
		rlIngress("cust4", "app", nil, "e.example.com"),
		// host-less rule can't be bound at the edge
		rlIngress("cust5", "app", map[string]string{RateLimitZoneAnnotation: "basic"}, ""),
	}
	got := buildRateLimitHostZone(ings)
	want := map[string]string{
		"a.example.com": "cust1/basic",
		"b.example.com": "cust1/basic",
		"c.example.com": "cust2/basic",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCollectIngressHosts(t *testing.T) {
	ings := []networking.Ingress{
		rlIngress("a", "x", nil, "B.example.com", "a.example.com"),
		rlIngress("b", "y", nil, "a.example.com", ""), // dup + empty
	}
	got := collectIngressHosts(ings)
	want := []string{"a.example.com", "b.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (lowercased, deduped, sorted)", got, want)
	}
}

func TestCollectLimitDocs(t *testing.T) {
	cms := []wafConfigMap{
		{namespace: "platform", name: "b-global", labels: map[string]string{RateLimitLabelKey: "global"},
			data: map[string]string{"z.yaml": "doc-b2", "a.yaml": "doc-b1"}},
		{namespace: "platform", name: "a-global", labels: map[string]string{RateLimitLabelKey: "global"},
			data: map[string]string{"l.yaml": "doc-a"}},
		// global outside podNamespace is a tenant injection attempt — ignored
		{namespace: "cust1", name: "evil-global", labels: map[string]string{RateLimitLabelKey: "global"},
			data: map[string]string{"x": "evil"}},
		{namespace: "cust1", name: "basic", labels: map[string]string{RateLimitLabelKey: "zone"},
			data: map[string]string{"l.yaml": "zone-doc"}},
	}

	global := collectGlobalLimitDocs(cms, "platform")
	// deterministic: ConfigMaps by namespace/name, data values by key
	want := []string{"doc-a", "doc-b1", "doc-b2"}
	if !reflect.DeepEqual(global, want) {
		t.Errorf("global docs: got %v, want %v", global, want)
	}

	zones := collectZoneLimitDocs(cms)
	if !reflect.DeepEqual(zones, map[string][]string{"cust1/basic": {"zone-doc"}}) {
		t.Errorf("zone docs: got %v", zones)
	}
}

func TestRateLimitStoreScopedAndGeneration(t *testing.T) {
	s := NewRateLimitStore()
	gen0 := s.gen.Load()
	s.SetGlobal([]string{"gdoc"})
	s.SetZones(map[string][]string{"cust1/basic": {"zdoc"}, "cust2/other": {"odoc"}})
	s.SetIngressDerived(
		map[string]string{"a.example.com": "cust1/basic", "d.example.com": "cust2/other"},
		[]string{"a.example.com", "d.example.com", "plain.example.com"},
	)
	if s.gen.Load() == gen0 {
		t.Fatal("generation should bump on content change")
	}

	// scope to an edge allowed only a.example.com + plain.example.com
	snap := s.scoped(func(host string) bool { return host != "d.example.com" })
	if !reflect.DeepEqual(snap.global, []string{"gdoc"}) {
		t.Errorf("global always included: got %v", snap.global)
	}
	if !reflect.DeepEqual(snap.hostZone, map[string]string{"a.example.com": "cust1/basic"}) {
		t.Errorf("hostZone not scoped: got %v", snap.hostZone)
	}
	if !reflect.DeepEqual(snap.zones, map[string][]string{"cust1/basic": {"zdoc"}}) {
		t.Errorf("zones must include only referenced+allowed: got %v", snap.zones)
	}
	if !reflect.DeepEqual(snap.hosts, []string{"a.example.com", "plain.example.com"}) {
		t.Errorf("hosts not scoped: got %v", snap.hosts)
	}

	// unchanged content must not bump the generation (etag stability)
	gen := s.gen.Load()
	s.SetGlobal([]string{"gdoc"})
	if s.gen.Load() != gen {
		t.Error("generation bumped on identical content")
	}
}

func TestServerRateLimitEndpoint(t *testing.T) {
	store := NewRateLimitStore()
	store.SetGlobal([]string{"gdoc"})
	store.SetZones(map[string][]string{"cust1/basic": {"zdoc"}})
	store.SetIngressDerived(map[string]string{"acme.com": "cust1/basic", "evil.com": "cust1/basic"}, []string{"acme.com", "evil.com"})

	authz := NewAuthz(map[string][]string{"tok": {"acme.com"}})
	h := NewServer(NewCertStore(), authz).WithRateLimit(store).Handler()

	// happy path, scoped to the token's domains
	req := httptest.NewRequest("GET", "/v1/ratelimit", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var resp rateLimitResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resp.GlobalLimits, []string{"gdoc"}) {
		t.Errorf("global: got %v", resp.GlobalLimits)
	}
	if !reflect.DeepEqual(resp.HostZoneMap, map[string]string{"acme.com": "cust1/basic"}) {
		t.Errorf("host_zone_map must exclude evil.com: got %v", resp.HostZoneMap)
	}
	if !reflect.DeepEqual(resp.Hosts, []string{"acme.com"}) {
		t.Errorf("hosts must be scoped: got %v", resp.Hosts)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}

	// 304 on matching If-None-Match
	req2 := httptest.NewRequest("GET", "/v1/ratelimit", nil)
	req2.Header.Set("Authorization", "Bearer tok")
	req2.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotModified {
		t.Errorf("want 304, got %d", rec2.Code)
	}

	// 401 without a token
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, httptest.NewRequest("GET", "/v1/ratelimit", nil))
	if rec3.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rec3.Code)
	}

	// 404 when distribution is disabled (no WithRateLimit)
	h2 := NewServer(NewCertStore(), authz).Handler()
	req4 := httptest.NewRequest("GET", "/v1/ratelimit", nil)
	req4.Header.Set("Authorization", "Bearer tok")
	rec4 := httptest.NewRecorder()
	h2.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec4.Code)
	}
}
