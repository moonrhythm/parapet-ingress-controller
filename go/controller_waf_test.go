package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/moonrhythm/parapet-ingress-controller/go/proxy"
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

func TestReloadWAF(t *testing.T) {
	t.Parallel()

	ctrl := newWAFController()

	ctrl.watchedConfigMaps.Store("ctrl-ns/waf-global", wafCM("ctrl-ns", "waf-global", wafRoleGlobal, `
rules:
  - id: block-scanners
    expression: request.user_agent.contains("sqlmap")
    action: block
`))
	ctrl.watchedConfigMaps.Store("cust1/acme", wafCM("cust1", "acme", wafRoleZone, `
rules:
  - id: block-admin
    expression: request.path.startsWith("/admin")
    action: block
`))
	// a global ruleset outside the controller's namespace must be ignored
	// (tenants can't inject baseline rules).
	ctrl.watchedConfigMaps.Store("cust1/waf-global", wafCM("cust1", "waf-global", wafRoleGlobal, `
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

	ctrl.watchedConfigMaps.Store("cust1/acme", wafCM("cust1", "acme", wafRoleZone, `
rules:
  - id: ok
    expression: request.path.startsWith("/x")
    action: block
`))
	ctrl.reloadWAFDebounced()
	require.Equal(t, []string{"ok"}, ctrl.LookupZone("cust1/acme").Rules())

	// push a broken rule (uncompilable expression) into the same zone
	ctrl.watchedConfigMaps.Store("cust1/acme", wafCM("cust1", "acme", wafRoleZone, `
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

func TestReloadWAF_DisabledIsNoop(t *testing.T) {
	t.Parallel()

	ctrl := New("", proxy.New())
	// WAF disabled: InitWAF builds nothing, reload is a no-op, no panic.
	ctrl.InitWAF()
	assert.NotPanics(t, ctrl.reloadWAFDebounced)
	assert.Nil(t, ctrl.GlobalWAF())
	assert.Nil(t, ctrl.LookupZone("any/zone"))
}
