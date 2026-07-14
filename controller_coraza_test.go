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

func newCorazaController() *Controller {
	ctrl := New("", proxy.New())
	ctrl.PodNamespace = "ctrl-ns"
	ctrl.CorazaConfig = CorazaConfig{Enabled: true}
	ctrl.InitCoraza()
	return ctrl
}

func corazaCM(namespace, name, role, rules string) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{corazaLabelKey: role},
		},
		Data: map[string]string{"rules.conf": rules},
	}
}

const denyAttackURI = `
SecRuleEngine On
SecRule REQUEST_URI "@contains /attack" "id:5001,phase:1,deny,status:403,msg:'attack'"
`

const denyAdminURI = `
SecRuleEngine On
SecRule REQUEST_URI "@contains /admin" "id:5002,phase:1,deny,status:403,msg:'admin'"
`

func serveCoraza(t *testing.T, mw interface {
	ServeHandler(http.Handler) http.Handler
}, path string) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "http://app"+path, nil)
	w := httptest.NewRecorder()
	mw.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, r)
	return w.Code
}

func TestReloadCoraza_GlobalAndZone(t *testing.T) {
	t.Parallel()

	ctrl := newCorazaController()

	ctrl.watchedCorazaConfigMaps.Store("ctrl-ns/coraza-global", corazaCM("ctrl-ns", "coraza-global", roleGlobal, denyAttackURI))
	ctrl.watchedCorazaConfigMaps.Store("cust1/acme", corazaCM("cust1", "acme", roleZone, denyAdminURI))
	// a global ruleset outside the controller namespace must be ignored.
	ctrl.watchedCorazaConfigMaps.Store("cust1/coraza-global", corazaCM("cust1", "coraza-global", roleGlobal, denyAttackURI))

	ctrl.reloadCorazaDebounced()

	assert.True(t, ctrl.globalCoraza.Loaded(), "global ruleset compiled")
	assert.Equal(t, http.StatusForbidden, serveCoraza(t, ctrl.GlobalCoraza(), "/attack"))
	assert.Equal(t, http.StatusOK, serveCoraza(t, ctrl.GlobalCoraza(), "/safe"))

	zone := ctrl.LookupCorazaZone("cust1/acme")
	require.NotNil(t, zone, "zone resolves by <namespace>/<name>")
	assert.Equal(t, http.StatusForbidden, serveCoraza(t, zone, "/admin"))
	assert.Equal(t, http.StatusOK, serveCoraza(t, zone, "/other"))

	assert.Nil(t, ctrl.LookupCorazaZone("cust1/missing"), "unknown zone resolves to nil")
}

// "global off, one zone on" — the toggle the user asked for: no global
// ConfigMap, only a zone ConfigMap. The global instance is a pass-through while
// the bound zone enforces.
func TestReloadCoraza_GlobalOffZoneOn(t *testing.T) {
	t.Parallel()

	ctrl := newCorazaController()
	ctrl.watchedCorazaConfigMaps.Store("cust1/acme", corazaCM("cust1", "acme", roleZone, denyAdminURI))
	ctrl.reloadCorazaDebounced()

	assert.False(t, ctrl.globalCoraza.Loaded(), "no global ConfigMap -> global is a pass-through")
	assert.Equal(t, http.StatusOK, serveCoraza(t, ctrl.GlobalCoraza(), "/admin"), "global off lets everything through")

	zone := ctrl.LookupCorazaZone("cust1/acme")
	require.NotNil(t, zone)
	assert.Equal(t, http.StatusForbidden, serveCoraza(t, zone, "/admin"), "the bound zone still enforces")
}

func TestReloadCoraza_BadZoneKeepsLastGood(t *testing.T) {
	t.Parallel()

	ctrl := newCorazaController()
	ctrl.watchedCorazaConfigMaps.Store("cust1/acme", corazaCM("cust1", "acme", roleZone, denyAdminURI))
	ctrl.reloadCorazaDebounced()
	require.Equal(t, http.StatusForbidden, serveCoraza(t, ctrl.LookupCorazaZone("cust1/acme"), "/admin"))

	// push a broken ruleset into the same zone
	ctrl.watchedCorazaConfigMaps.Store("cust1/acme", corazaCM("cust1", "acme", roleZone, "SecRule totally not valid )("))
	ctrl.reloadCorazaDebounced()

	zone := ctrl.LookupCorazaZone("cust1/acme")
	require.NotNil(t, zone)
	assert.Equal(t, http.StatusForbidden, serveCoraza(t, zone, "/admin"), "bad edit must not drop the live ruleset")
}

func TestReloadCoraza_UnchangedZoneReusesInstance(t *testing.T) {
	t.Parallel()

	ctrl := newCorazaController()
	ctrl.watchedCorazaConfigMaps.Store("cust1/acme", corazaCM("cust1", "acme", roleZone, denyAdminURI))
	ctrl.reloadCorazaDebounced()
	acme1 := ctrl.LookupCorazaZone("cust1/acme")
	require.NotNil(t, acme1)

	// byte-for-byte identical reload reuses the compiled instance (no recompile).
	ctrl.reloadCorazaDebounced()
	assert.Same(t, acme1, ctrl.LookupCorazaZone("cust1/acme"),
		"unchanged zone reuses its compiled instance across reloads")
}

func TestReloadCoraza_AddRemoveZones(t *testing.T) {
	t.Parallel()

	ctrl := newCorazaController()
	ctrl.watchedCorazaConfigMaps.Store("cust1/acme", corazaCM("cust1", "acme", roleZone, denyAdminURI))
	ctrl.reloadCorazaDebounced()
	acme1 := ctrl.LookupCorazaZone("cust1/acme")
	require.NotNil(t, acme1)

	ctrl.watchedCorazaConfigMaps.Store("cust2/beta", corazaCM("cust2", "beta", roleZone, denyAttackURI))
	ctrl.reloadCorazaDebounced()
	assert.Same(t, acme1, ctrl.LookupCorazaZone("cust1/acme"), "existing zone survives an add")
	require.NotNil(t, ctrl.LookupCorazaZone("cust2/beta"), "added zone is compiled")

	ctrl.watchedCorazaConfigMaps.Delete("cust1/acme")
	ctrl.reloadCorazaDebounced()
	assert.Nil(t, ctrl.LookupCorazaZone("cust1/acme"), "removed zone drops from the registry")
	require.NotNil(t, ctrl.LookupCorazaZone("cust2/beta"), "untouched zone remains")
}

func TestReloadCoraza_ConcurrentReloadsRaceFree(t *testing.T) {
	t.Parallel()

	ctrl := newCorazaController()
	ctrl.watchedCorazaConfigMaps.Store("ctrl-ns/coraza-global", corazaCM("ctrl-ns", "coraza-global", roleGlobal, denyAttackURI))
	for _, z := range []string{"acme", "beta", "gamma"} {
		ctrl.watchedCorazaConfigMaps.Store("cust/"+z, corazaCM("cust", z, roleZone, denyAdminURI))
	}

	const workers = 6
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				ctrl.reloadCorazaDebounced()
			}
		}()
	}
	wg.Wait()

	assert.True(t, ctrl.globalCoraza.Loaded())
	require.NotNil(t, ctrl.LookupCorazaZone("cust/acme"))
	require.NotNil(t, ctrl.LookupCorazaZone("cust/gamma"))
}

func TestReloadCoraza_IgnoresMultiLabeledConfigMap(t *testing.T) {
	t.Parallel()

	ctrl := newCorazaController()
	cm := corazaCM("cust", "acme", roleZone, denyAttackURI)
	// also labeled for the WAF: a ConfigMap must carry one feature label, else
	// both reloaders consume its data and cross-parse to empty/garbage sets.
	cm.Labels[wafLabelKey] = roleZone
	ctrl.watchedCorazaConfigMaps.Store("cust/acme", cm)
	ctrl.reloadCorazaDebounced()

	assert.Nil(t, ctrl.LookupCorazaZone("cust/acme"),
		"a multi-feature-labeled configmap is refused by the coraza reload")
}

func TestReloadCoraza_DisabledIsNoop(t *testing.T) {
	t.Parallel()

	ctrl := New("", proxy.New())
	ctrl.InitCoraza() // disabled: builds nothing
	assert.NotPanics(t, ctrl.reloadCorazaDebounced)
	assert.Nil(t, ctrl.GlobalCoraza())
	assert.Nil(t, ctrl.LookupCorazaZone("any/zone"))
}
