package controller

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/moonrhythm/parapet-ingress-controller/proxy"
)

func newTransformController() *Controller {
	ctrl := New("", proxy.New())
	ctrl.PodNamespace = "ctrl-ns"
	ctrl.TransformConfig = TransformConfig{Enabled: true}
	ctrl.InitTransform()
	return ctrl
}

func transformCM(namespace, name, doc string) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{transformLabelKey: roleZone},
		},
		Data: map[string]string{"transforms.yaml": doc},
	}
}

const transformOneRule = `
transforms:
- id: hsts
  phase: response
  ops:
  - type: set-header
    name: Strict-Transport-Security
    value: max-age=63072000
  priority: 0
`

func TestReloadTransform(t *testing.T) {
	t.Parallel()

	ctrl := newTransformController()
	ctrl.watchedTransformConfigMaps.Store("cust1/transform-42", transformCM("cust1", "transform-42", transformOneRule))
	ctrl.reloadTransformDebounced()

	zone := ctrl.LookupTransformZone("cust1/transform-42")
	require.NotNil(t, zone, "zone resolves by <namespace>/<name>")
	assert.Equal(t, []string{"hsts"}, zone.IDs())

	assert.Nil(t, ctrl.LookupTransformZone("cust1/missing"), "unknown zone resolves to nil")
}

func TestReloadTransform_BadZoneKeepsLastGood(t *testing.T) {
	t.Parallel()

	ctrl := newTransformController()
	ctrl.watchedTransformConfigMaps.Store("cust1/transform-42", transformCM("cust1", "transform-42", transformOneRule))
	ctrl.reloadTransformDebounced()
	require.Equal(t, []string{"hsts"}, ctrl.LookupTransformZone("cust1/transform-42").IDs())

	// push a set with an uncompilable CEL filter (api can't catch this; the
	// controller rejects the whole set all-or-nothing).
	ctrl.watchedTransformConfigMaps.Store("cust1/transform-42", transformCM("cust1", "transform-42", `
transforms:
- id: broken
  phase: request
  filter: "this is not && valid cel ("
  ops:
  - type: set-header
    name: X-Test
    value: "1"
  priority: 0
`))
	ctrl.reloadTransformDebounced()

	zone := ctrl.LookupTransformZone("cust1/transform-42")
	require.NotNil(t, zone)
	assert.Equal(t, []string{"hsts"}, zone.IDs(), "bad edit must not drop the live set")
}

func TestReloadTransform_UnchangedZoneReusesInstance(t *testing.T) {
	t.Parallel()

	ctrl := newTransformController()
	ctrl.watchedTransformConfigMaps.Store("cust1/transform-42", transformCM("cust1", "transform-42", transformOneRule))
	ctrl.reloadTransformDebounced()

	first := ctrl.LookupTransformZone("cust1/transform-42")
	require.NotNil(t, first)

	// identical input: the compiled Zone is reused (same pointer, no recompile).
	ctrl.reloadTransformDebounced()
	assert.Same(t, first, ctrl.LookupTransformZone("cust1/transform-42"),
		"unchanged input reuses the compiled zone")
}

func TestReloadTransform_RemoveZone(t *testing.T) {
	t.Parallel()

	ctrl := newTransformController()
	ctrl.watchedTransformConfigMaps.Store("cust1/transform-42", transformCM("cust1", "transform-42", transformOneRule))
	ctrl.reloadTransformDebounced()
	require.NotNil(t, ctrl.LookupTransformZone("cust1/transform-42"))

	// the deployer deletes the ConfigMap on transform.delete; the next reload
	// drops the zone (the plugin then passes traffic through unmodified).
	ctrl.watchedTransformConfigMaps.Delete("cust1/transform-42")
	ctrl.reloadTransformDebounced()
	assert.Nil(t, ctrl.LookupTransformZone("cust1/transform-42"), "deleted zone is gone after reload")
}

func globalTransformCM(namespace, name, doc string) *v1.ConfigMap {
	cm := transformCM(namespace, name, doc)
	cm.Labels[transformLabelKey] = roleGlobal
	return cm
}

const transformGlobalRule = `
transforms:
- id: robots
  phase: response
  ops:
  - type: set-header
    name: X-Robots-Tag
    value: noindex, nofollow
  priority: 0
`

func TestReloadTransform_Global(t *testing.T) {
	t.Parallel()

	ctrl := newTransformController()
	ctrl.watchedTransformConfigMaps.Store("ctrl-ns/transform-global", globalTransformCM("ctrl-ns", "transform-global", transformGlobalRule))
	ctrl.reloadTransformDebounced()

	// the global set serves through the mounted middleware end-to-end.
	h := ctrl.GlobalTransform().ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, "noindex, nofollow", w.Header().Get("X-Robots-Tag"),
		"global response op applies to all traffic")

	// deleting the global ConfigMap drops the set back to a pass-through.
	ctrl.watchedTransformConfigMaps.Delete("ctrl-ns/transform-global")
	ctrl.reloadTransformDebounced()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Empty(t, w.Header().Get("X-Robots-Tag"), "deleted global set is gone after reload")
}

func TestReloadTransform_GlobalOutsidePodNamespaceIgnored(t *testing.T) {
	t.Parallel()

	ctrl := newTransformController()
	ctrl.watchedTransformConfigMaps.Store("cust1/transform-global", globalTransformCM("cust1", "transform-global", transformGlobalRule))
	ctrl.reloadTransformDebounced()

	assert.Nil(t, ctrl.globalTransform.Load(),
		"a tenant-namespace global set must not mutate all traffic")
}

func TestReloadTransform_BadGlobalKeepsLastGood(t *testing.T) {
	t.Parallel()

	ctrl := newTransformController()
	ctrl.watchedTransformConfigMaps.Store("ctrl-ns/transform-global", globalTransformCM("ctrl-ns", "transform-global", transformGlobalRule))
	ctrl.reloadTransformDebounced()
	require.NotNil(t, ctrl.globalTransform.Load())

	ctrl.watchedTransformConfigMaps.Store("ctrl-ns/transform-global", globalTransformCM("ctrl-ns", "transform-global", `
transforms:
- id: broken
  phase: response
  filter: "this is not && valid cel ("
  ops:
  - type: set-header
    name: X-Test
    value: "1"
  priority: 0
`))
	ctrl.reloadTransformDebounced()

	z := ctrl.globalTransform.Load()
	require.NotNil(t, z)
	assert.Equal(t, []string{"robots"}, z.IDs(), "bad edit must not drop the live global set")

	// a fixed edit applies (the rejected input didn't advance the fingerprint).
	ctrl.watchedTransformConfigMaps.Store("ctrl-ns/transform-global", globalTransformCM("ctrl-ns", "transform-global", `
transforms:
- id: robots-v2
  phase: response
  ops:
  - type: set-header
    name: X-Robots-Tag
    value: none
  priority: 0
`))
	ctrl.reloadTransformDebounced()
	assert.Equal(t, []string{"robots-v2"}, ctrl.globalTransform.Load().IDs())
}

func TestGlobalTransform_DisabledReturnsNil(t *testing.T) {
	t.Parallel()

	ctrl := New("", proxy.New())
	assert.Nil(t, ctrl.GlobalTransform(), "disabled transform mounts nothing")
}

func TestReloadTransform_IgnoresMultiLabeledConfigMap(t *testing.T) {
	t.Parallel()

	ctrl := newTransformController()
	cm := transformCM("cust1", "transform-42", transformOneRule)
	// a ConfigMap that also carries the waf label must be ignored (one ConfigMap
	// per feature, by deployer policy).
	cm.Labels[wafLabelKey] = roleZone
	ctrl.watchedTransformConfigMaps.Store("cust1/transform-42", cm)
	ctrl.reloadTransformDebounced()

	assert.Nil(t, ctrl.LookupTransformZone("cust1/transform-42"),
		"a multi-feature-labeled configmap is not consumed as transform input")
}
