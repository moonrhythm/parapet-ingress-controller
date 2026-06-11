package edgecp

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleExposition = `# HELP parapet_requests_total Number of requests
# TYPE parapet_requests_total counter
parapet_requests_total{host="acme.com"} 42
# HELP parapet_edge_refresh_total Successful control-plane polls
# TYPE parapet_edge_refresh_total counter
parapet_edge_refresh_total{edge_id="self-reported"} 7
`

// metricsTestServer builds a Server with ingestion enabled: one token WITH an id
// grant, one without.
func metricsTestServer(ttl time.Duration) (*Server, *MetricsStore) {
	authz := NewAuthzEntries(map[string]Entry{
		"edge-tok": {ID: "edge-a", Domains: []string{"*"}},
		"no-id":    {Domains: []string{"*"}},
	})
	store := NewMetricsStore(ttl)
	srv := NewServer(NewCertStore(), authz).WithMetricsIngest(store)
	return srv, store
}

func pushReq(h http.Handler, auth, instance, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/metrics", strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", "Bearer "+auth)
	}
	if instance != "" {
		r.Header.Set("X-Edge-Instance", instance)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func parseExposition(t *testing.T, body string) map[string]*dto.MetricFamily {
	t.Helper()
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(body))
	require.NoError(t, err, "merged /metrics output must re-parse as valid text exposition")
	return families
}

func labelValue(m *dto.Metric, name string) string {
	for _, lp := range m.Label {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}

func TestMetricsStore_IngestInjectsAndOverridesLabels(t *testing.T) {
	store := NewMetricsStore(time.Minute)
	require.NoError(t, store.Ingest("edge-a", "pod-1", strings.NewReader(sampleExposition)))

	fams := store.families()
	byName := map[string]*dto.MetricFamily{}
	for _, mf := range fams {
		byName[mf.GetName()] = mf
	}

	// A label-less series gains both labels.
	req := byName["parapet_requests_total"]
	require.NotNil(t, req)
	require.Len(t, req.Metric, 1)
	assert.Equal(t, "edge-a", labelValue(req.Metric[0], "edge_id"))
	assert.Equal(t, "pod-1", labelValue(req.Metric[0], "edge_instance"))
	assert.Equal(t, "acme.com", labelValue(req.Metric[0], "host"))

	// A self-reported edge_id is OVERRIDDEN by the server-derived identity.
	refresh := byName["parapet_edge_refresh_total"]
	require.NotNil(t, refresh)
	assert.Equal(t, "edge-a", labelValue(refresh.Metric[0], "edge_id"))

	// Label pairs stay sorted by name (the dto/expfmt contract).
	for _, mf := range fams {
		for _, m := range mf.Metric {
			for i := 1; i < len(m.Label); i++ {
				assert.LessOrEqual(t, m.Label[i-1].GetName(), m.Label[i].GetName())
			}
		}
	}
}

func TestMetricsStore_BadBodyStoresNothing(t *testing.T) {
	store := NewMetricsStore(time.Minute)
	require.Error(t, store.Ingest("edge-a", "pod-1", strings.NewReader("this is { not exposition\nformat===")))
	assert.Empty(t, store.families())
}

func TestMetricsStore_InstancesUnderOneEdgeIDCoexist(t *testing.T) {
	store := NewMetricsStore(time.Minute)
	require.NoError(t, store.Ingest("edge-a", "pod-1", strings.NewReader(sampleExposition)))
	require.NoError(t, store.Ingest("edge-a", "pod-2", strings.NewReader(sampleExposition)))

	// No clobber: both instances' series are live, distinguished by edge_instance.
	instances := map[string]bool{}
	for _, mf := range store.families() {
		if mf.GetName() != "parapet_requests_total" {
			continue
		}
		for _, m := range mf.Metric {
			instances[labelValue(m, "edge_instance")] = true
		}
	}
	assert.Equal(t, map[string]bool{"pod-1": true, "pod-2": true}, instances)

	// A re-push for one instance replaces only that instance's snapshot.
	require.NoError(t, store.Ingest("edge-a", "pod-1", strings.NewReader(sampleExposition)))
	count := 0
	for _, mf := range store.families() {
		if mf.GetName() == "parapet_requests_total" {
			count += len(mf.Metric)
		}
	}
	assert.Equal(t, 2, count)
}

func TestMetricsStore_InstanceCapEvictsStalest(t *testing.T) {
	store := NewMetricsStore(time.Hour)
	now := time.Unix(1000, 0)
	store.now = func() time.Time { return now }

	for i := 0; i < maxEdgeMetricsInstances; i++ {
		now = now.Add(time.Second)
		require.NoError(t, store.Ingest("edge-a", "pod-"+strconv.Itoa(i), strings.NewReader(sampleExposition)))
	}
	// A different identity is NOT affected by edge-a's cap.
	now = now.Add(time.Second)
	require.NoError(t, store.Ingest("edge-b", "pod-x", strings.NewReader(sampleExposition)))

	// One past the cap: pod-0 (stalest) is evicted, the new instance lands.
	now = now.Add(time.Second)
	require.NoError(t, store.Ingest("edge-a", "pod-new", strings.NewReader(sampleExposition)))

	live := map[string]bool{}
	for _, mf := range store.families() {
		for _, m := range mf.Metric {
			if labelValue(m, "edge_id") == "edge-a" {
				live[labelValue(m, "edge_instance")] = true
			}
		}
	}
	assert.Len(t, live, maxEdgeMetricsInstances)
	assert.False(t, live["pod-0"], "stalest instance must be evicted at the cap")
	assert.True(t, live["pod-new"])
	assert.True(t, live["pod-1"])

	// Re-pushing an EXISTING instance never evicts (replacement, not growth).
	now = now.Add(time.Second)
	require.NoError(t, store.Ingest("edge-a", "pod-new", strings.NewReader(sampleExposition)))
	count := 0
	for _, mf := range store.families() {
		if mf.GetName() != "parapet_requests_total" {
			continue
		}
		for _, m := range mf.Metric {
			if labelValue(m, "edge_id") == "edge-a" {
				count++
			}
		}
	}
	assert.Equal(t, maxEdgeMetricsInstances, count)
}

func TestMetricsStore_TTLEviction(t *testing.T) {
	store := NewMetricsStore(time.Minute)
	now := time.Unix(1000, 0)
	store.now = func() time.Time { return now }

	require.NoError(t, store.Ingest("edge-a", "pod-1", strings.NewReader(sampleExposition)))
	now = now.Add(30 * time.Second)
	require.NoError(t, store.Ingest("edge-a", "pod-2", strings.NewReader(sampleExposition)))

	// 61s after pod-1's push (31s after pod-2's): only pod-1 expires.
	now = now.Add(31 * time.Second)
	live := map[string]bool{}
	for _, mf := range store.families() {
		for _, m := range mf.Metric {
			live[labelValue(m, "edge_instance")] = true
		}
	}
	assert.Equal(t, map[string]bool{"pod-2": true}, live)

	// The evicted instance's freshness series is deleted with it; the live one stays.
	assert.Equal(t, 0, deleteCheckGaugeCount(t, "edge-a", "pod-1"))
	assert.Equal(t, 1, deleteCheckGaugeCount(t, "edge-a", "pod-2"))
}

// deleteCheckGaugeCount reports whether the freshness gauge still has a series for
// (edgeID, instance) — Delete returns true when the series existed.
func deleteCheckGaugeCount(t *testing.T, edgeID, instance string) int {
	t.Helper()
	if edgeMetricsLastPush.DeleteLabelValues(edgeID, instance) {
		// Put nothing back: callers only run this at the end of a test.
		return 1
	}
	return 0
}

func TestMergeFamilies_SingleBlockPerFamily(t *testing.T) {
	store := NewMetricsStore(time.Minute)
	require.NoError(t, store.Ingest("edge-a", "pod-1", strings.NewReader(sampleExposition)))
	require.NoError(t, store.Ingest("edge-b", "pod-9", strings.NewReader(sampleExposition)))

	rec := httptest.NewRecorder()
	MetricsHandler(store).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// The merged output must re-parse as valid exposition (proves one HELP/TYPE
	// block per family even when several edges push the same family).
	families := parseExposition(t, body)

	// Both edges' series are present in ONE family.
	req := families["parapet_requests_total"]
	require.NotNil(t, req)
	ids := map[string]bool{}
	for _, m := range req.Metric {
		ids[labelValue(m, "edge_id")] = true
	}
	assert.True(t, ids["edge-a"] && ids["edge-b"])
	assert.Equal(t, 1, strings.Count(body, "# TYPE parapet_requests_total "))

	// The CP's own registry rides the same response (any parapet_edge_ca_* family
	// from the shared registry suffices; signer gauges register in this package).
	assert.Contains(t, body, "parapet_edge_metrics_last_push_seconds")
}

func TestMergeFamilies_TypeConflictDropsEdgeFamily(t *testing.T) {
	counter := dto.MetricType_COUNTER
	gauge := dto.MetricType_GAUGE
	name := "demo_metric"
	v := 1.0
	own := []*dto.MetricFamily{{
		Name: &name, Type: &counter,
		Metric: []*dto.Metric{{Counter: &dto.Counter{Value: &v}}},
	}}
	edge := []*dto.MetricFamily{{
		Name: &name, Type: &gauge,
		Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: &v}}},
	}}
	out := mergeFamilies(own, edge)
	require.Len(t, out, 1)
	assert.Equal(t, dto.MetricType_COUNTER, out[0].GetType())
	assert.Len(t, out[0].Metric, 1) // the conflicting edge family was dropped whole
}

func TestMergeFamilies_DoesNotMutateInputs(t *testing.T) {
	counter := dto.MetricType_COUNTER
	name := "demo_total"
	v := 1.0
	base := &dto.MetricFamily{Name: &name, Type: &counter, Metric: []*dto.Metric{{Counter: &dto.Counter{Value: &v}}}}
	other := &dto.MetricFamily{Name: &name, Type: &counter, Metric: []*dto.Metric{{Counter: &dto.Counter{Value: &v}}}}
	mergeFamilies([]*dto.MetricFamily{base}, []*dto.MetricFamily{other})
	assert.Len(t, base.Metric, 1, "merge must copy, not append into a stored snapshot")
	assert.Len(t, other.Metric, 1)
}

func TestMetricsPushAPI(t *testing.T) {
	srv, store := metricsTestServer(time.Minute)
	h := srv.Handler()

	t.Run("disabled is 404", func(t *testing.T) {
		off := NewServer(NewCertStore(), NewAuthz(nil)).Handler()
		assert.Equal(t, http.StatusNotFound, pushReq(off, "edge-tok", "pod-1", sampleExposition).Code)
	})
	t.Run("unknown token is 401", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, pushReq(h, "", "pod-1", sampleExposition).Code)
		assert.Equal(t, http.StatusUnauthorized, pushReq(h, "bogus", "pod-1", sampleExposition).Code)
	})
	t.Run("token without id grant is 403", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, pushReq(h, "no-id", "pod-1", sampleExposition).Code)
	})
	t.Run("missing instance header is 400", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, pushReq(h, "edge-tok", "", sampleExposition).Code)
	})
	t.Run("oversized instance header is 400", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, pushReq(h, "edge-tok", strings.Repeat("x", maxInstanceLen+1), sampleExposition).Code)
	})
	t.Run("garbage body is 400", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, pushReq(h, "edge-tok", "pod-1", "not { exposition ===").Code)
	})
	t.Run("oversized body is 413", func(t *testing.T) {
		big := sampleExposition + strings.Repeat("# padding padding padding\n", maxEdgeMetricsBody/26+1)
		assert.Equal(t, http.StatusRequestEntityTooLarge, pushReq(h, "edge-tok", "pod-1", big).Code)
	})
	t.Run("ok push is 204 and lands with server-derived identity", func(t *testing.T) {
		assert.Equal(t, http.StatusNoContent, pushReq(h, "edge-tok", "pod-1", sampleExposition).Code)

		rec := httptest.NewRecorder()
		MetricsHandler(store).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
		require.Equal(t, http.StatusOK, rec.Code)
		families := parseExposition(t, rec.Body.String())
		req := families["parapet_requests_total"]
		require.NotNil(t, req)
		found := false
		for _, m := range req.Metric {
			if labelValue(m, "edge_id") == "edge-a" && labelValue(m, "edge_instance") == "pod-1" {
				found = true
			}
		}
		assert.True(t, found, "pushed series must carry the token-derived edge_id and the instance label")
	})
}
