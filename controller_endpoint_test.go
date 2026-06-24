package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// legacyEndpoints builds a core/v1 Endpoints object (named after its Service)
// with all addresses ready, for the no-EndpointSlice fallback tests.
func legacyEndpoints(namespace, name string, ips ...string) *v1.Endpoints {
	ep := &v1.Endpoints{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	if len(ips) > 0 {
		addrs := make([]v1.EndpointAddress, 0, len(ips))
		for _, ip := range ips {
			addrs = append(addrs, v1.EndpointAddress{IP: ip})
		}
		ep.Subsets = []v1.EndpointSubset{{Addresses: addrs}}
	}
	return ep
}

// endpointSlice builds an IPv4 EndpointSlice for namespace/svcName (carrying the
// kubernetes.io/service-name label the controller maps back to a host). All
// addresses are ready. sliceName is the slice's own object name — a Service may
// own several, so tests vary it to model multiple slices per Service.
func endpointSlice(namespace, svcName, sliceName string, ips ...string) *discovery.EndpointSlice {
	es := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      sliceName,
			Labels:    map[string]string{discovery.LabelServiceName: svcName},
		},
		AddressType: discovery.AddressTypeIPv4,
	}
	for _, ip := range ips {
		es.Endpoints = append(es.Endpoints, discovery.Endpoint{Addresses: []string{ip}})
	}
	return es
}

// TestReloadEndpointSlice checks that the per-event EndpointSlice path
// (reloadEndpointSlice, driven off the watched-slices store) leaves the route
// table in the same state a full reloadEndpointDebounced rebuild would, for the
// cases that matter on pod churn: add a host, change a host's IPs, two slices
// unioning into one host, delete a slice, delete a host, and a no-op re-upsert.
func TestReloadEndpointSlice(t *testing.T) {
	t.Parallel()

	// port routing so Lookup resolves host -> ip:port
	setPorts := func(c *Controller) {
		c.routeTable.SetPortRoutes(map[string]string{
			"a.default.svc.cluster.local:80": "8080",
			"b.default.svc.cluster.local:80": "8080",
		})
	}

	// incremental controller, driven only through the watch-event entry points:
	// store the slice (as watchResource does) then recompute its service.
	var incr Controller
	setPorts(&incr)
	upsert := func(es *discovery.EndpointSlice) {
		incr.watchedEndpointSlices.Store(es.Namespace+"/"+es.Name, es)
		incr.reloadEndpointSlice(es)
	}
	del := func(es *discovery.EndpointSlice) {
		incr.watchedEndpointSlices.Delete(es.Namespace + "/" + es.Name)
		incr.reloadEndpointSlice(es)
	}

	// full-rebuild controller, kept in lock-step via the watched-slices store.
	// desired is the current intended set; rebuild relists it like initial sync.
	var full Controller
	setPorts(&full)
	desired := map[string]*discovery.EndpointSlice{}
	rebuild := func() {
		full.watchedEndpointSlices.Range(func(k, _ any) bool { full.watchedEndpointSlices.Delete(k); return true })
		for _, es := range desired {
			full.watchedEndpointSlices.Store(es.Namespace+"/"+es.Name, es)
		}
		full.reloadEndpointDebounced()
	}

	// backendSet collects the distinct backends a host round-robins over. Only the
	// SET of reachable pod IPs is well-defined: a host's IPs are unioned across
	// several slices in nondeterministic (sync.Map.Range) order, and each Table
	// keeps its own rotation counter, so a single Lookup is not comparable between
	// the incremental and full-rebuild tables — the set is.
	backendSet := func(c *Controller, host string) map[string]bool {
		set := map[string]bool{}
		for i := 0; i < 20; i++ {
			set[c.routeTable.Lookup(host+":80")] = true
		}
		return set
	}
	assertSame := func(host string) {
		t.Helper()
		assert.Equal(t,
			backendSet(&full, host),
			backendSet(&incr, host),
			"incremental and full-rebuild disagree for %s", host)
	}

	// add host a (single slice)
	desired["default/a-1"] = endpointSlice("default", "a", "a-1", "10.0.0.1")
	upsert(desired["default/a-1"])
	rebuild()
	assert.Equal(t, "10.0.0.1:8080", incr.routeTable.Lookup("a.default.svc.cluster.local:80"))
	assertSame("a.default.svc.cluster.local")

	// add host b
	desired["default/b-1"] = endpointSlice("default", "b", "b-1", "10.0.1.1", "10.0.1.2")
	upsert(desired["default/b-1"])
	rebuild()
	assertSame("b.default.svc.cluster.local")

	// add a SECOND slice for host a — its IPs union with the first slice's
	desired["default/a-2"] = endpointSlice("default", "a", "a-2", "10.0.0.2")
	upsert(desired["default/a-2"])
	rebuild()
	// both slices' pod IPs are reachable through the one host route (round-robin)
	assert.Equal(t, map[string]bool{"10.0.0.1:8080": true, "10.0.0.2:8080": true},
		backendSet(&incr, "a.default.svc.cluster.local"))
	assertSame("a.default.svc.cluster.local")

	// change host a's first slice IP
	desired["default/a-1"] = endpointSlice("default", "a", "a-1", "10.0.0.9")
	upsert(desired["default/a-1"])
	rebuild()
	assertSame("a.default.svc.cluster.local")

	// no-op re-upsert of host a's first slice (same IP)
	upsert(desired["default/a-1"])
	rebuild()
	assertSame("a.default.svc.cluster.local")

	// delete host a's SECOND slice — host a survives on its remaining slice
	delete(desired, "default/a-2")
	del(endpointSlice("default", "a", "a-2", "10.0.0.2"))
	rebuild()
	assert.Equal(t, "10.0.0.9:8080", incr.routeTable.Lookup("a.default.svc.cluster.local:80"))
	assertSame("a.default.svc.cluster.local")

	// delete host b (its only slice) -> host route is gone
	delete(desired, "default/b-1")
	del(endpointSlice("default", "b", "b-1"))
	rebuild()
	assert.Empty(t, incr.routeTable.Lookup("b.default.svc.cluster.local:80"))
	assertSame("b.default.svc.cluster.local")
	// host a is untouched by b's deletion
	assert.Equal(t, "10.0.0.9:8080", incr.routeTable.Lookup("a.default.svc.cluster.local:80"))
	assertSame("a.default.svc.cluster.local")
}

// TestEndpointSliceFallbackToEndpoints checks the no-slice fallback: a Service
// with only a legacy Endpoints object routes from it, an EndpointSlice takes
// over the moment one appears (slices are authoritative — even an empty slice
// suppresses the fallback), and removing the slice restores the fallback.
func TestEndpointSliceFallbackToEndpoints(t *testing.T) {
	t.Parallel()

	const host = "c.default.svc.cluster.local"
	newCtrl := func() *Controller {
		var c Controller
		c.routeTable.SetPortRoutes(map[string]string{host + ":80": "8080"})
		return &c
	}

	t.Run("incremental: endpoints -> slice wins -> slice removed restores fallback", func(t *testing.T) {
		c := newCtrl()

		// only legacy Endpoints exist -> routed from them
		ep := legacyEndpoints("default", "c", "10.0.0.50")
		c.watchedEndpoints.Store("default/c", ep)
		c.reloadEndpointsObject(ep)
		assert.Equal(t, "10.0.0.50:8080", c.routeTable.Lookup(host+":80"))

		// a slice appears -> it is authoritative, the legacy IP is dropped
		sl := endpointSlice("default", "c", "c-1", "10.0.0.60")
		c.watchedEndpointSlices.Store("default/c-1", sl)
		c.reloadEndpointSlice(sl)
		assert.Equal(t, "10.0.0.60:8080", c.routeTable.Lookup(host+":80"))

		// an empty slice still suppresses the fallback (slices authoritative)
		empty := endpointSlice("default", "c", "c-1")
		c.watchedEndpointSlices.Store("default/c-1", empty)
		c.reloadEndpointSlice(empty)
		assert.Empty(t, c.routeTable.Lookup(host+":80"))

		// slice removed -> fallback to legacy Endpoints restored
		c.watchedEndpointSlices.Delete("default/c-1")
		c.reloadEndpointSlice(empty)
		assert.Equal(t, "10.0.0.50:8080", c.routeTable.Lookup(host+":80"))
	})

	t.Run("full rebuild: slice wins over endpoints for the same service", func(t *testing.T) {
		c := newCtrl()
		c.watchedEndpoints.Store("default/c", legacyEndpoints("default", "c", "10.0.0.50"))

		// endpoints-only -> rebuild routes from them
		c.reloadEndpointDebounced()
		assert.Equal(t, "10.0.0.50:8080", c.routeTable.Lookup(host+":80"))

		// add a slice -> rebuild prefers it
		c.watchedEndpointSlices.Store("default/c-1", endpointSlice("default", "c", "c-1", "10.0.0.60"))
		c.reloadEndpointDebounced()
		assert.Equal(t, "10.0.0.60:8080", c.routeTable.Lookup(host+":80"))
	})

	t.Run("resolveTargetPort falls back to Endpoints named port", func(t *testing.T) {
		c := newCtrl()
		svc := namedPortService("default", "c", "http", 80)

		// no slice, no endpoints -> unresolved
		_, ok := c.resolveTargetPort(svc, svc.Spec.Ports[0])
		assert.False(t, ok)

		// legacy Endpoints carry the named port -> resolved from them
		ep := legacyEndpoints("default", "c", "10.0.0.50")
		ep.Subsets[0].Ports = []v1.EndpointPort{{Name: "http", Port: 8080}}
		c.watchedEndpoints.Store("default/c", ep)
		got, ok := c.resolveTargetPort(svc, svc.Spec.Ports[0])
		assert.True(t, ok)
		assert.Equal(t, "8080", got)

		// once a slice exists with the port, it is authoritative
		c.watchedEndpointSlices.Store("default/c-1", endpointSliceNamedPort("default", "c", "c-1", "10.0.0.60", "http", 9090))
		got, ok = c.resolveTargetPort(svc, svc.Spec.Ports[0])
		assert.True(t, ok)
		assert.Equal(t, "9090", got)
	})
}
