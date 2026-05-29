package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func endpoints(namespace, name string, ips ...string) *v1.Endpoints {
	ep := &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
	}
	if len(ips) > 0 {
		addrs := make([]v1.EndpointAddress, 0, len(ips))
		for _, ip := range ips {
			addrs = append(addrs, v1.EndpointAddress{IP: ip})
		}
		ep.Subsets = []v1.EndpointSubset{{Addresses: addrs}}
	}
	return ep
}

// TestReloadSingleEndpoint checks that the per-event endpoint path
// (reloadSingleEndpoint upsert / deleteSingleEndpoint delete) leaves the route
// table in the same state a full reloadEndpointDebounced rebuild would, for the
// four cases that matter on pod churn: add a host, change a host's IPs, delete a
// host, and a no-op re-upsert.
func TestReloadSingleEndpoint(t *testing.T) {
	t.Parallel()

	// port routing so Lookup resolves host -> ip:port
	setPorts := func(c *Controller) {
		c.routeTable.SetPortRoutes(map[string]string{
			"a.default.svc.cluster.local:80": "8080",
			"b.default.svc.cluster.local:80": "8080",
		})
	}

	// incremental controller, driven only through the watch-event entry points
	var incr Controller
	setPorts(&incr)

	// full-rebuild controller, kept in lock-step via the watched-endpoints store.
	// desired is the current intended set; rebuild relists it like initial sync.
	var full Controller
	setPorts(&full)
	desired := map[string]*v1.Endpoints{}
	rebuild := func() {
		full.watchedEndpoints.Range(func(k, _ any) bool { full.watchedEndpoints.Delete(k); return true })
		for _, ep := range desired {
			full.watchedEndpoints.Store(ep.Namespace+"/"+ep.Name, ep)
		}
		full.reloadEndpointDebounced()
	}

	assertSame := func(host string) {
		t.Helper()
		assert.Equal(t,
			full.routeTable.Lookup(host+":80"),
			incr.routeTable.Lookup(host+":80"),
			"incremental and full-rebuild disagree for %s", host)
	}

	// add host a
	desired["default/a"] = endpoints("default", "a", "10.0.0.1")
	incr.reloadSingleEndpoint(desired["default/a"])
	rebuild()
	assert.Equal(t, "10.0.0.1:8080", incr.routeTable.Lookup("a.default.svc.cluster.local:80"))
	assertSame("a.default.svc.cluster.local")

	// add host b
	desired["default/b"] = endpoints("default", "b", "10.0.1.1", "10.0.1.2")
	incr.reloadSingleEndpoint(desired["default/b"])
	rebuild()
	assertSame("b.default.svc.cluster.local")

	// change host a's IP
	desired["default/a"] = endpoints("default", "a", "10.0.0.9")
	incr.reloadSingleEndpoint(desired["default/a"])
	rebuild()
	assert.Equal(t, "10.0.0.9:8080", incr.routeTable.Lookup("a.default.svc.cluster.local:80"))
	assertSame("a.default.svc.cluster.local")

	// no-op re-upsert of host a (same IP)
	incr.reloadSingleEndpoint(desired["default/a"])
	rebuild()
	assert.Equal(t, "10.0.0.9:8080", incr.routeTable.Lookup("a.default.svc.cluster.local:80"))
	assertSame("a.default.svc.cluster.local")

	// delete host b
	delete(desired, "default/b")
	incr.deleteSingleEndpoint(endpoints("default", "b"))
	rebuild()
	assert.Empty(t, incr.routeTable.Lookup("b.default.svc.cluster.local:80"))
	assertSame("b.default.svc.cluster.local")
	// host a is untouched by b's deletion
	assert.Equal(t, "10.0.0.9:8080", incr.routeTable.Lookup("a.default.svc.cluster.local:80"))
	assertSame("a.default.svc.cluster.local")
}
