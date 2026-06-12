package controller

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/moonrhythm/parapet-ingress-controller/proxy"
)

func newRLController() *Controller {
	ctrl := New("", proxy.New())
	ctrl.PodNamespace = "ctrl-ns"
	ctrl.RateLimitConfig = RateLimitConfig{Enabled: true}
	ctrl.InitRateLimit()
	return ctrl
}

func rlCM(namespace, name, role, doc string) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{rateLimitLabelKey: role},
		},
		Data: map[string]string{"limits.yaml": doc},
	}
}

const rlOneLimit = `
limits:
  - id: per-ip
    rate: 1
    window: 1h
`

func TestReloadRateLimit(t *testing.T) {
	t.Parallel()

	ctrl := newRLController()

	ctrl.watchedRLConfigMaps.Store("ctrl-ns/rl-global", rlCM("ctrl-ns", "rl-global", roleGlobal, `
limits:
  - id: baseline
    rate: 100
    window: 1m
`))
	ctrl.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, rlOneLimit))
	// a global set outside the controller's namespace must be ignored (a tenant
	// can't throttle other tenants' traffic).
	ctrl.watchedRLConfigMaps.Store("cust1/rl-global", rlCM("cust1", "rl-global", roleGlobal, `
limits:
  - id: tenant-injected
    rate: 1
    window: 1s
`))

	ctrl.reloadRateLimitDebounced()

	assert.Equal(t, []string{"baseline"}, ctrl.globalRateLimit.IDs(),
		"only the in-namespace global set is honored")

	zone := ctrl.LookupRateLimitZone("cust1/acme")
	require.NotNil(t, zone, "zone resolves by <namespace>/<name>")
	assert.Equal(t, []string{"per-ip"}, zone.IDs())

	assert.Nil(t, ctrl.LookupRateLimitZone("cust1/missing"), "unknown zone resolves to nil")
}

func TestReloadRateLimit_BadZoneKeepsLastGood(t *testing.T) {
	t.Parallel()

	ctrl := newRLController()

	ctrl.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, rlOneLimit))
	ctrl.reloadRateLimitDebounced()
	require.Equal(t, []string{"per-ip"}, ctrl.LookupRateLimitZone("cust1/acme").IDs())

	// push a broken set (window out of bounds) into the same zone
	ctrl.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, `
limits:
  - id: broken
    rate: 1
    window: 48h
`))
	ctrl.reloadRateLimitDebounced()

	zone := ctrl.LookupRateLimitZone("cust1/acme")
	require.NotNil(t, zone)
	assert.Equal(t, []string{"per-ip"}, zone.IDs(), "bad edit must not drop the live set")
}

func TestReloadRateLimit_UnchangedZoneReusesInstance(t *testing.T) {
	t.Parallel()

	ctrl := newRLController()

	ctrl.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, rlOneLimit))
	ctrl.watchedRLConfigMaps.Store("cust2/beta", rlCM("cust2", "beta", roleZone, `
limits:
  - id: x
    rate: 5
    window: 1m
`))
	ctrl.reloadRateLimitDebounced()

	acme1 := ctrl.LookupRateLimitZone("cust1/acme")
	beta1 := ctrl.LookupRateLimitZone("cust2/beta")
	require.NotNil(t, acme1)
	require.NotNil(t, beta1)

	// Identical input: both instances reused (no SetLimits — counters intact).
	ctrl.reloadRateLimitDebounced()
	assert.Same(t, acme1, ctrl.LookupRateLimitZone("cust1/acme"))
	assert.Same(t, beta1, ctrl.LookupRateLimitZone("cust2/beta"))

	// A sibling zone's edit must not reapply an unchanged zone.
	ctrl.watchedRLConfigMaps.Store("cust2/beta", rlCM("cust2", "beta", roleZone, `
limits:
  - id: y
    rate: 5
    window: 1m
`))
	ctrl.reloadRateLimitDebounced()
	assert.Same(t, acme1, ctrl.LookupRateLimitZone("cust1/acme"))
	assert.Equal(t, []string{"y"}, ctrl.LookupRateLimitZone("cust2/beta").IDs(),
		"the edited zone is reapplied")
}

func TestReloadRateLimit_ChangedZoneKeepsCounters(t *testing.T) {
	t.Parallel()

	// An edit that doesn't touch a limit's shaping config (here: adding a
	// sibling limit) must not reset the existing limit's consumed budget —
	// the zone Limiter instance is reused and SetLimits carries strategies over.
	ctrl := newRLController()
	ctrl.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, rlOneLimit))
	ctrl.reloadRateLimitDebounced()

	zone := ctrl.LookupRateLimitZone("cust1/acme")
	require.NotNil(t, zone)

	take := func() bool {
		r := httptest.NewRequest(http.MethodGet, "http://app/", nil)
		r.Header.Set("X-Real-Ip", "1.2.3.4")
		w := httptest.NewRecorder()
		var called bool
		zone.Serve(w, r, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		return called
	}
	require.True(t, take())
	require.False(t, take(), "budget spent")

	ctrl.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, rlOneLimit+`
  - id: second
    rate: 100
    window: 1m
`))
	ctrl.reloadRateLimitDebounced()

	same := ctrl.LookupRateLimitZone("cust1/acme")
	assert.Same(t, zone, same, "changed zone reuses the same Limiter instance")
	assert.Equal(t, []string{"per-ip", "second"}, same.IDs())
	assert.False(t, take(), "per-ip's spent budget survived the edit")
}

func TestReloadRateLimit_AddRemoveZones(t *testing.T) {
	t.Parallel()

	ctrl := newRLController()
	ctrl.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, rlOneLimit))
	ctrl.reloadRateLimitDebounced()
	acme1 := ctrl.LookupRateLimitZone("cust1/acme")
	require.NotNil(t, acme1)

	ctrl.watchedRLConfigMaps.Store("cust2/beta", rlCM("cust2", "beta", roleZone, rlOneLimit))
	ctrl.reloadRateLimitDebounced()
	assert.Same(t, acme1, ctrl.LookupRateLimitZone("cust1/acme"), "existing zone survives an add")
	require.NotNil(t, ctrl.LookupRateLimitZone("cust2/beta"))

	ctrl.watchedRLConfigMaps.Delete("cust1/acme")
	ctrl.reloadRateLimitDebounced()
	assert.Nil(t, ctrl.LookupRateLimitZone("cust1/acme"), "removed zone drops from the registry")
	require.NotNil(t, ctrl.LookupRateLimitZone("cust2/beta"))

	ctrl.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, rlOneLimit))
	ctrl.reloadRateLimitDebounced()
	readd := ctrl.LookupRateLimitZone("cust1/acme")
	require.NotNil(t, readd)
	assert.NotSame(t, acme1, readd, "a re-added zone is a fresh instance")
}

func TestReloadRateLimit_GlobalReusedAndRebuilt(t *testing.T) {
	t.Parallel()

	ctrl := newRLController()
	ctrl.watchedRLConfigMaps.Store("ctrl-ns/rl", rlCM("ctrl-ns", "rl", roleGlobal, rlOneLimit))
	ctrl.reloadRateLimitDebounced()
	require.Equal(t, []string{"per-ip"}, ctrl.globalRateLimit.IDs())
	fp1 := ctrl.globalRLFingerprint
	require.NotEmpty(t, fp1)

	ctrl.reloadRateLimitDebounced()
	assert.Equal(t, fp1, ctrl.globalRLFingerprint, "unchanged global input is not reapplied")

	ctrl.watchedRLConfigMaps.Store("ctrl-ns/rl", rlCM("ctrl-ns", "rl", roleGlobal, `
limits:
  - id: other
    rate: 5
    window: 1m
`))
	ctrl.reloadRateLimitDebounced()
	assert.NotEqual(t, fp1, ctrl.globalRLFingerprint, "changed global input advances the fingerprint")
	assert.Equal(t, []string{"other"}, ctrl.globalRateLimit.IDs())
}

func TestReloadRateLimit_BadGlobalRetried(t *testing.T) {
	t.Parallel()

	// A rejected global edit must not advance the fingerprint, so the next
	// reload retries it instead of skipping (mirrors the WAF reload contract).
	ctrl := newRLController()
	ctrl.watchedRLConfigMaps.Store("ctrl-ns/rl", rlCM("ctrl-ns", "rl", roleGlobal, `
limits:
  - id: broken
    rate: 0
    window: 1m
`))
	ctrl.reloadRateLimitDebounced()
	assert.Empty(t, ctrl.globalRLFingerprint, "rejected input must not be fingerprinted as applied")

	ctrl.watchedRLConfigMaps.Store("ctrl-ns/rl", rlCM("ctrl-ns", "rl", roleGlobal, rlOneLimit))
	ctrl.reloadRateLimitDebounced()
	assert.Equal(t, []string{"per-ip"}, ctrl.globalRateLimit.IDs())
}

func TestReloadRateLimit_BothLabelsSkipped(t *testing.T) {
	t.Parallel()

	ctrl := newRLController()
	cm := rlCM("cust1", "acme", roleZone, rlOneLimit)
	cm.Labels[wafLabelKey] = roleZone // also labeled for the WAF
	ctrl.watchedRLConfigMaps.Store("cust1/acme", cm)
	ctrl.reloadRateLimitDebounced()

	assert.Nil(t, ctrl.LookupRateLimitZone("cust1/acme"),
		"a configmap labeled for both features is refused by the ratelimit reload")
}

func TestReloadRateLimit_GlobalEndToEnd(t *testing.T) {
	t.Parallel()

	ctrl := newRLController()
	ctrl.watchedRLConfigMaps.Store("ctrl-ns/rl", rlCM("ctrl-ns", "rl", roleGlobal, rlOneLimit))
	ctrl.reloadRateLimitDebounced()

	h := ctrl.GlobalRateLimit().ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	do := func() int {
		r := httptest.NewRequest(http.MethodGet, "http://app/", nil)
		r.Header.Set("X-Real-Ip", "9.9.9.9")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	assert.Equal(t, http.StatusOK, do())
	assert.Equal(t, http.StatusTooManyRequests, do())
}

func TestReloadRateLimit_ConcurrentReloadsRaceFree(t *testing.T) {
	t.Parallel()

	ctrl := newRLController()
	ctrl.watchedRLConfigMaps.Store("ctrl-ns/rl", rlCM("ctrl-ns", "rl", roleGlobal, rlOneLimit))
	for _, z := range []string{"acme", "beta", "gamma", "delta"} {
		ctrl.watchedRLConfigMaps.Store("cust/"+z, rlCM("cust", z, roleZone, rlOneLimit))
	}

	// The debounce does not guarantee single-flight execution, so two passes can
	// overlap; without rlReloadMu this trips `go test -race` on the fingerprint
	// string/map (see the wafReloadMu precedent).
	const workers = 6
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ctrl.reloadRateLimitDebounced()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, []string{"per-ip"}, ctrl.globalRateLimit.IDs())
	require.NotNil(t, ctrl.LookupRateLimitZone("cust/acme"))
	require.NotNil(t, ctrl.LookupRateLimitZone("cust/delta"))
}

func TestReloadRateLimit_DisabledIsNoop(t *testing.T) {
	t.Parallel()

	ctrl := New("", proxy.New())
	// disabled: InitRateLimit builds nothing, reload is a no-op, no panic.
	ctrl.InitRateLimit()
	assert.NotPanics(t, ctrl.reloadRateLimitDebounced)
	assert.Nil(t, ctrl.GlobalRateLimit())
	assert.Nil(t, ctrl.LookupRateLimitZone("any/zone"))
}

func TestReloadRateLimit_MalformedYAMLKeepsLastGoodAndRetries(t *testing.T) {
	t.Parallel()

	// Parse (unlike SetLimits) returns PARTIAL results alongside its error; the
	// reload must reject the whole batch on a Parse error — never apply the
	// partial set — and must not advance the fingerprint, so the bad input is
	// retried once fixed.
	ctrl := newRLController()

	// global
	ctrl.watchedRLConfigMaps.Store("ctrl-ns/rl", rlCM("ctrl-ns", "rl", roleGlobal, rlOneLimit))
	ctrl.reloadRateLimitDebounced()
	require.Equal(t, []string{"per-ip"}, ctrl.globalRateLimit.IDs())
	goodFP := ctrl.globalRLFingerprint

	badCM := rlCM("ctrl-ns", "rl", roleGlobal, `{not yaml`)
	badCM.Data["zz-valid.yaml"] = `
limits:
  - id: partial
    rate: 5
    window: 1m
`
	ctrl.watchedRLConfigMaps.Store("ctrl-ns/rl", badCM)
	ctrl.reloadRateLimitDebounced()
	assert.Equal(t, []string{"per-ip"}, ctrl.globalRateLimit.IDs(),
		"a malformed document rejects the batch; the parsable sibling must not apply")
	assert.Equal(t, goodFP, ctrl.globalRLFingerprint,
		"a rejected batch must not advance the fingerprint (it is retried, not skipped)")

	ctrl.watchedRLConfigMaps.Store("ctrl-ns/rl", rlCM("ctrl-ns", "rl", roleGlobal, `
limits:
  - id: fixed-up
    rate: 5
    window: 1m
`))
	ctrl.reloadRateLimitDebounced()
	assert.Equal(t, []string{"fixed-up"}, ctrl.globalRateLimit.IDs(), "the fixed edit applies")

	// zone
	ctrl.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, rlOneLimit))
	ctrl.reloadRateLimitDebounced()
	require.Equal(t, []string{"per-ip"}, ctrl.LookupRateLimitZone("cust1/acme").IDs())

	ctrl.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, `{not yaml`))
	ctrl.reloadRateLimitDebounced()
	assert.Equal(t, []string{"per-ip"}, ctrl.LookupRateLimitZone("cust1/acme").IDs(),
		"a malformed zone document keeps the zone's last-good set")

	ctrl.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, `
limits:
  - id: zone-fixed
    rate: 5
    window: 1m
`))
	ctrl.reloadRateLimitDebounced()
	assert.Equal(t, []string{"zone-fixed"}, ctrl.LookupRateLimitZone("cust1/acme").IDs(),
		"the fixed zone edit applies (bad input was retried, not fingerprint-skipped)")
}

func TestReloadRateLimit_KnownHostWiredOnGlobalAndZones(t *testing.T) {
	t.Parallel()

	// The unknown-Host collapse must flow from the controller's route state into
	// BOTH the global limiter (InitRateLimit) and zone limiters (reload): random
	// Hosts share one bucket, served Hosts get their own. Zones need it because
	// host-less catch-all ingress rules route any Host into the bound zone.
	ctrl := newRLController()
	ctrl.routes.Store(&routeState{
		mux:        http.NewServeMux(),
		knownHosts: map[string]struct{}{"app.example.com": {}},
	})

	const hostLimit = `
limits:
  - id: per-host
    key: host
    rate: 1
    window: 1h
`
	ctrl.watchedRLConfigMaps.Store("ctrl-ns/rl", rlCM("ctrl-ns", "rl", roleGlobal, hostLimit))
	ctrl.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, hostLimit))
	ctrl.reloadRateLimitDebounced()

	drive := func(serve func(w http.ResponseWriter, r *http.Request) bool, host string) bool {
		r := httptest.NewRequest(http.MethodGet, "http://placeholder/", nil)
		r.Host = host
		w := httptest.NewRecorder()
		return serve(w, r)
	}

	globalHandler := ctrl.GlobalRateLimit().ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	viaGlobal := func(w http.ResponseWriter, r *http.Request) bool {
		rec := w.(*httptest.ResponseRecorder)
		globalHandler.ServeHTTP(rec, r)
		return rec.Code == http.StatusOK
	}
	assert.True(t, drive(viaGlobal, "app.example.com"), "served host: own bucket")
	assert.False(t, drive(viaGlobal, "app.example.com"))
	assert.True(t, drive(viaGlobal, "rnd1.attacker.test"))
	assert.False(t, drive(viaGlobal, "rnd2.attacker.test"),
		"global: unknown hosts collapse into one shared bucket")

	zone := ctrl.LookupRateLimitZone("cust1/acme")
	require.NotNil(t, zone)
	viaZone := func(w http.ResponseWriter, r *http.Request) bool {
		var called bool
		zone.Serve(w, r, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		return called
	}
	assert.True(t, drive(viaZone, "rnd3.attacker.test"))
	assert.False(t, drive(viaZone, "rnd4.attacker.test"),
		"zone: unknown hosts collapse into one shared bucket too")
	assert.True(t, drive(viaZone, "app.example.com"), "zone: served host keeps its own bucket")
}

func TestReloadRateLimit_MetricNamesWired(t *testing.T) {
	t.Parallel()

	// Contract: ConfigMap-driven limits emit parapet_ratelimit_total with names
	// "global:<id>" and "zone:<ns>/<name>:<id>" — the literal prefixes live in
	// the controller wiring, so assert them through the real prom registry (a
	// dropped "zone:" prefix would silently merge series with the annotation
	// limiters' "<ns>/<ingress>:<s|m|h>" names).
	ctrl := newRLController()
	ctrl.watchedRLConfigMaps.Store("ctrl-ns/rl-metrics", rlCM("ctrl-ns", "rl-metrics", roleGlobal, `
limits:
  - id: glimit
    rate: 100
    window: 1m
`))
	ctrl.watchedRLConfigMaps.Store("metrics-ns/mz", rlCM("metrics-ns", "mz", roleZone, `
limits:
  - id: zlimit
    rate: 100
    window: 1m
`))
	ctrl.reloadRateLimitDebounced()

	r := httptest.NewRequest(http.MethodGet, "http://app/", nil)
	r.Header.Set("X-Real-Ip", "203.0.113.7")
	ctrl.GlobalRateLimit().ServeHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(httptest.NewRecorder(), r)
	ctrl.LookupRateLimitZone("metrics-ns/mz").
		Serve(httptest.NewRecorder(), r, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	families, err := prom.Registry().Gather()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, mf := range families {
		if mf.GetName() != "parapet_ratelimit_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "name" {
					names[lp.GetValue()] = true
				}
			}
		}
	}
	assert.True(t, names["global:glimit"], "global limits emit name=global:<id> (got %v)", names)
	assert.True(t, names["zone:metrics-ns/mz:zlimit"], "zone limits emit name=zone:<ns>/<name>:<id> (got %v)", names)
}

func TestReloadRateLimit_GeoKeyResolversWired(t *testing.T) {
	t.Parallel()

	// RateLimitConfig's GeoIP resolvers must flow into the global limiter AND
	// zone limiters, so asn/country keys compile; without them SetLimits
	// rejects such limits (keep-last-good) instead of bucketing everyone
	// together.
	const asnLimit = `
limits:
  - id: per-asn
    key: asn
    rate: 1
    window: 1h
`
	ctrl := newRLController() // no resolvers wired
	ctrl.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, asnLimit))
	ctrl.reloadRateLimitDebounced()
	zone := ctrl.LookupRateLimitZone("cust1/acme")
	require.NotNil(t, zone)
	assert.Empty(t, zone.IDs(), "asn key without a resolver is rejected (zone enforces nothing rather than mis-bucketing)")

	ctrl2 := New("", proxy.New())
	ctrl2.PodNamespace = "ctrl-ns"
	ctrl2.RateLimitConfig = RateLimitConfig{
		Enabled: true,
		ASN:     func(*http.Request) int64 { return 64500 },
		Country: func(*http.Request) string { return "TH" },
	}
	ctrl2.InitRateLimit()
	ctrl2.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, asnLimit))
	ctrl2.watchedRLConfigMaps.Store("ctrl-ns/rl", rlCM("ctrl-ns", "rl", roleGlobal, `
limits:
  - id: per-country
    key: country
    rate: 1
    window: 1h
`))
	ctrl2.reloadRateLimitDebounced()
	require.Equal(t, []string{"per-asn"}, ctrl2.LookupRateLimitZone("cust1/acme").IDs())
	require.Equal(t, []string{"per-country"}, ctrl2.globalRateLimit.IDs())

	// Everyone resolves to the same ASN -> one shared bucket: second request 429.
	zone2 := ctrl2.LookupRateLimitZone("cust1/acme")
	do := func() bool {
		r := httptest.NewRequest(http.MethodGet, "http://app/", nil)
		w := httptest.NewRecorder()
		var called bool
		zone2.Serve(w, r, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		return called
	}
	assert.True(t, do())
	assert.False(t, do(), "asn key resolves through the wired resolver")
}

func TestReloadRateLimit_FilterMacroKnobWired(t *testing.T) {
	t.Parallel()

	// A limit `filter` is bounded by the same operator knob as a WAF rule:
	// FilterDisableMacros (set from WAF_DISABLE_MACROS) must flow into the
	// global + zone limiters so a macro-using filter is refused at compile —
	// proving the wiring, not just the default. The expression is a CEL macro
	// (exists), which compiles by default but is rejected when macros are off.
	const macroFilter = `
limits:
  - id: f
    rate: 1
    window: 1h
    filter: request.headers.exists(k, k == "x-api-key")
`
	// Default config (macros on): the filter compiles, the limit loads.
	on := newRLController()
	on.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, macroFilter))
	on.reloadRateLimitDebounced()
	require.Equal(t, []string{"f"}, on.LookupRateLimitZone("cust1/acme").IDs(),
		"macros enabled by default: filter compiles")

	// DisableMacros wired through config: the same filter is rejected, so the
	// zone keeps its (empty) last-good set instead of loading the limit.
	off := New("", proxy.New())
	off.PodNamespace = "ctrl-ns"
	off.RateLimitConfig = RateLimitConfig{Enabled: true, FilterDisableMacros: true}
	off.InitRateLimit()
	off.watchedRLConfigMaps.Store("cust1/acme", rlCM("cust1", "acme", roleZone, macroFilter))
	off.reloadRateLimitDebounced()
	zone := off.LookupRateLimitZone("cust1/acme")
	require.NotNil(t, zone)
	assert.Empty(t, zone.IDs(), "FilterDisableMacros wired: macro filter rejected, last-good kept")
}
