package controller

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/moonrhythm/parapet-ingress-controller/proxy"
)

func newWAFController() *Controller {
	ctrl := New("", proxy.New())
	ctrl.PodNamespace = "ctrl-ns"
	ctrl.WAFConfig = WAFConfig{Enabled: true}
	ctrl.InitWAF()
	return ctrl
}

func wafCM(namespace, name, role, rules string) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{wafLabelKey: role},
		},
		Data: map[string]string{"rules.yaml": rules},
	}
}

func TestWAFCountryResolverWired(t *testing.T) {
	t.Parallel()

	// A WAFConfig.Country resolver must reach request.country in the compiled
	// WAFs (global + zones) via newWAF -> parapet WAF.Country.
	ctrl := New("", proxy.New())
	ctrl.PodNamespace = "ctrl-ns"
	ctrl.WAFConfig = WAFConfig{
		Enabled: true,
		Country: func(_ *http.Request) string { return "CN" },
	}
	ctrl.InitWAF()
	ctrl.watchedConfigMaps.Store("ctrl-ns/waf-global", wafCM("ctrl-ns", "waf-global", roleGlobal, `
rules:
  - id: block-cn
    expression: request.country == "CN"
    action: block
`))
	ctrl.reloadWAFDebounced()

	r := httptest.NewRequest(http.MethodGet, "http://app/", nil)
	w := httptest.NewRecorder()
	ctrl.GlobalWAF().ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code, "request.country resolver blocks via the global WAF")
}

func TestReloadWAF(t *testing.T) {
	t.Parallel()

	ctrl := newWAFController()

	ctrl.watchedConfigMaps.Store("ctrl-ns/waf-global", wafCM("ctrl-ns", "waf-global", roleGlobal, `
rules:
  - id: block-scanners
    expression: request.user_agent.contains("sqlmap")
    action: block
`))
	ctrl.watchedConfigMaps.Store("cust1/acme", wafCM("cust1", "acme", roleZone, `
rules:
  - id: block-admin
    expression: request.path.startsWith("/admin")
    action: block
`))
	// a global ruleset outside the controller's namespace must be ignored
	// (tenants can't inject baseline rules).
	ctrl.watchedConfigMaps.Store("cust1/waf-global", wafCM("cust1", "waf-global", roleGlobal, `
rules:
  - id: tenant-injected-global
    expression: "true"
    action: block
`))

	ctrl.reloadWAFDebounced()

	assert.Equal(t, []string{"block-scanners"}, ctrl.globalWAF.Rules(),
		"only the in-namespace global ruleset is honored")

	zone := ctrl.LookupZone("cust1/acme")
	require.NotNil(t, zone, "zone resolves by <namespace>/<name>")
	assert.Equal(t, []string{"block-admin"}, zone.Rules())

	assert.Nil(t, ctrl.LookupZone("cust1/missing"), "unknown zone resolves to nil")
}

func TestReloadWAF_BadZoneKeepsLastGood(t *testing.T) {
	t.Parallel()

	ctrl := newWAFController()

	ctrl.watchedConfigMaps.Store("cust1/acme", wafCM("cust1", "acme", roleZone, `
rules:
  - id: ok
    expression: request.path.startsWith("/x")
    action: block
`))
	ctrl.reloadWAFDebounced()
	require.Equal(t, []string{"ok"}, ctrl.LookupZone("cust1/acme").Rules())

	// push a broken rule (uncompilable expression) into the same zone
	ctrl.watchedConfigMaps.Store("cust1/acme", wafCM("cust1", "acme", roleZone, `
rules:
  - id: broken
    expression: this is not cel
    action: block
`))
	ctrl.reloadWAFDebounced()

	// the zone keeps its last-good ruleset — the instance is reused and SetRules
	// is all-or-nothing, so a bad edit can't drop the live ruleset.
	zone := ctrl.LookupZone("cust1/acme")
	require.NotNil(t, zone)
	assert.Equal(t, []string{"ok"}, zone.Rules(), "bad edit must not drop the live ruleset")
}

func TestReloadWAF_UnchangedZoneReusesInstance(t *testing.T) {
	t.Parallel()

	ctrl := newWAFController()

	const acmeRules = `
rules:
  - id: block-admin
    expression: request.path.startsWith("/admin")
    action: block
`
	ctrl.watchedConfigMaps.Store("cust1/acme", wafCM("cust1", "acme", roleZone, acmeRules))
	ctrl.watchedConfigMaps.Store("cust2/beta", wafCM("cust2", "beta", roleZone, `
rules:
  - id: block-x
    expression: request.path.startsWith("/x")
    action: block
`))
	ctrl.reloadWAFDebounced()

	acme1 := ctrl.LookupZone("cust1/acme")
	beta1 := ctrl.LookupZone("cust2/beta")
	require.NotNil(t, acme1)
	require.NotNil(t, beta1)

	// Reload again with byte-for-byte identical ConfigMaps: every zone's compiled
	// instance must be reused (same pointer), i.e. no recompile happened.
	ctrl.reloadWAFDebounced()
	assert.Same(t, acme1, ctrl.LookupZone("cust1/acme"),
		"unchanged zone reuses its compiled instance across reloads")
	assert.Same(t, beta1, ctrl.LookupZone("cust2/beta"),
		"unchanged zone reuses its compiled instance across reloads")

	// A reload triggered by an unrelated zone change must still reuse the
	// untouched zone's instance.
	ctrl.watchedConfigMaps.Store("cust2/beta", wafCM("cust2", "beta", roleZone, `
rules:
  - id: block-y
    expression: request.path.startsWith("/y")
    action: block
`))
	ctrl.reloadWAFDebounced()
	assert.Same(t, acme1, ctrl.LookupZone("cust1/acme"),
		"a sibling zone's edit must not recompile an unchanged zone")
	assert.Equal(t, []string{"block-y"}, ctrl.LookupZone("cust2/beta").Rules(),
		"the edited zone is recompiled")
}

func TestReloadWAF_ChangedZoneRebuilt(t *testing.T) {
	t.Parallel()

	ctrl := newWAFController()
	ctrl.watchedConfigMaps.Store("cust1/acme", wafCM("cust1", "acme", roleZone, `
rules:
  - id: block-admin
    expression: request.path.startsWith("/admin")
    action: block
`))
	ctrl.reloadWAFDebounced()
	require.Equal(t, []string{"block-admin"}, ctrl.LookupZone("cust1/acme").Rules())

	// Change the rule input -> recompiled, new ruleset live (same reused instance).
	ctrl.watchedConfigMaps.Store("cust1/acme", wafCM("cust1", "acme", roleZone, `
rules:
  - id: block-api
    expression: request.path.startsWith("/api")
    action: block
`))
	ctrl.reloadWAFDebounced()
	assert.Equal(t, []string{"block-api"}, ctrl.LookupZone("cust1/acme").Rules(),
		"changed zone is recompiled to the new ruleset")
}

func TestReloadWAF_AddRemoveZones(t *testing.T) {
	t.Parallel()

	ctrl := newWAFController()
	ctrl.watchedConfigMaps.Store("cust1/acme", wafCM("cust1", "acme", roleZone, `
rules:
  - id: block-admin
    expression: request.path.startsWith("/admin")
    action: block
`))
	ctrl.reloadWAFDebounced()
	acme1 := ctrl.LookupZone("cust1/acme")
	require.NotNil(t, acme1)

	// Add a second zone; the first must remain (and reuse its instance).
	ctrl.watchedConfigMaps.Store("cust2/beta", wafCM("cust2", "beta", roleZone, `
rules:
  - id: block-x
    expression: request.path.startsWith("/x")
    action: block
`))
	ctrl.reloadWAFDebounced()
	assert.Same(t, acme1, ctrl.LookupZone("cust1/acme"), "existing zone survives an add")
	require.NotNil(t, ctrl.LookupZone("cust2/beta"), "added zone is compiled")

	// Remove the first zone; it must drop out of the registry.
	ctrl.watchedConfigMaps.Delete("cust1/acme")
	ctrl.reloadWAFDebounced()
	assert.Nil(t, ctrl.LookupZone("cust1/acme"), "removed zone drops from the registry")
	require.NotNil(t, ctrl.LookupZone("cust2/beta"), "untouched zone remains")

	// Re-add the first zone with the original rules; it gets a fresh instance and
	// must be recompiled (its prior fingerprint was dropped with it).
	ctrl.watchedConfigMaps.Store("cust1/acme", wafCM("cust1", "acme", roleZone, `
rules:
  - id: block-admin
    expression: request.path.startsWith("/admin")
    action: block
`))
	ctrl.reloadWAFDebounced()
	readd := ctrl.LookupZone("cust1/acme")
	require.NotNil(t, readd)
	assert.NotSame(t, acme1, readd, "a re-added zone is a fresh compiled instance")
	assert.Equal(t, []string{"block-admin"}, readd.Rules())
}

func TestReloadWAF_GlobalReusedAndRebuilt(t *testing.T) {
	t.Parallel()

	ctrl := newWAFController()
	ctrl.watchedConfigMaps.Store("ctrl-ns/waf-global", wafCM("ctrl-ns", "waf-global", roleGlobal, `
rules:
  - id: block-scanners
    expression: request.user_agent.contains("sqlmap")
    action: block
`))
	ctrl.reloadWAFDebounced()
	require.Equal(t, []string{"block-scanners"}, ctrl.globalWAF.Rules())
	fp1 := ctrl.globalWAFFingerprint
	require.NotEmpty(t, fp1)

	// Unchanged global input: fingerprint stays put (no recompile path taken).
	ctrl.reloadWAFDebounced()
	assert.Equal(t, fp1, ctrl.globalWAFFingerprint, "unchanged global input is not recompiled")
	assert.Equal(t, []string{"block-scanners"}, ctrl.globalWAF.Rules())

	// Changed global input: recompiled, fingerprint advances.
	ctrl.watchedConfigMaps.Store("ctrl-ns/waf-global", wafCM("ctrl-ns", "waf-global", roleGlobal, `
rules:
  - id: block-bots
    expression: request.user_agent.contains("bot")
    action: block
`))
	ctrl.reloadWAFDebounced()
	assert.NotEqual(t, fp1, ctrl.globalWAFFingerprint, "changed global input advances the fingerprint")
	assert.Equal(t, []string{"block-bots"}, ctrl.globalWAF.Rules())
}

func TestReloadWAF_ConcurrentReloadsRaceFree(t *testing.T) {
	t.Parallel()

	ctrl := newWAFController()

	// Seed a global ruleset plus several zones so each pass read-modify-writes
	// both globalWAFFingerprint (string) and the zoneFingerprints map.
	ctrl.watchedConfigMaps.Store("ctrl-ns/waf-global", wafCM("ctrl-ns", "waf-global", roleGlobal, `
rules:
  - id: block-scanners
    expression: request.user_agent.contains("sqlmap")
    action: block
`))
	for _, z := range []string{"acme", "beta", "gamma", "delta"} {
		ctrl.watchedConfigMaps.Store("cust/"+z, wafCM("cust", z, roleZone, `
rules:
  - id: block-admin
    expression: request.path.startsWith("/admin")
    action: block
`))
	}

	// The debounce does not guarantee single-flight execution, so two
	// reloadWAFDebounced passes can overlap. Drive that directly: without
	// wafReloadMu this trips `go test -race` on globalWAFFingerprint /
	// zoneFingerprints (and can fatal on a concurrent map read+write).
	const workers = 6
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ctrl.reloadWAFDebounced()
			}
		}()
	}
	wg.Wait()

	// State stays consistent after the concurrent storm.
	assert.Equal(t, []string{"block-scanners"}, ctrl.globalWAF.Rules())
	require.NotNil(t, ctrl.LookupZone("cust/acme"))
	require.NotNil(t, ctrl.LookupZone("cust/delta"))
}

func TestReloadWAF_MultipleGlobalConfigMapsDeterministicOrder(t *testing.T) {
	t.Parallel()

	// Two global ConfigMaps in the controller namespace, each contributing one
	// equal-priority rule. The concatenation order must follow namespace/name
	// (waf-a before waf-b), not the random sync.Map.Range order — otherwise
	// equal-priority precedence and the fingerprint would flip between reloads.
	ctrl := newWAFController()
	ctrl.watchedConfigMaps.Store("ctrl-ns/waf-a", wafCM("ctrl-ns", "waf-a", roleGlobal, `
rules:
  - id: rule-a
    expression: "true"
    action: log
`))
	ctrl.watchedConfigMaps.Store("ctrl-ns/waf-b", wafCM("ctrl-ns", "waf-b", roleGlobal, `
rules:
  - id: rule-b
    expression: "true"
    action: log
`))

	// Reload many times: the order must be stable and sorted on every pass. Before
	// the deterministic sort, the random Range order flips this with high
	// probability across this many iterations.
	var firstFP string
	for i := 0; i < 20; i++ {
		ctrl.reloadWAFDebounced()
		assert.Equal(t, []string{"rule-a", "rule-b"}, ctrl.globalWAF.Rules(),
			"global rule order must be namespace/name-sorted and stable")
		if i == 0 {
			firstFP = ctrl.globalWAFFingerprint
		} else {
			assert.Equal(t, firstFP, ctrl.globalWAFFingerprint,
				"a stable concatenation order keeps the fingerprint stable (no needless recompile)")
		}
	}
}

func TestReloadWAF_DisabledIsNoop(t *testing.T) {
	t.Parallel()

	ctrl := New("", proxy.New())
	// WAF disabled: InitWAF builds nothing, reload is a no-op, no panic.
	ctrl.InitWAF()
	assert.NotPanics(t, ctrl.reloadWAFDebounced)
	assert.Nil(t, ctrl.GlobalWAF())
	assert.Nil(t, ctrl.LookupZone("any/zone"))
}
