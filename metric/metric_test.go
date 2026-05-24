package metric

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/moonrhythm/parapet-ingress-controller/state"
)

func TestHostGetMCaching(t *testing.T) {
	// same key returns the same cached handle
	a := _host.getM("cache-test.example.com", "")
	b := _host.getM("cache-test.example.com", "")
	assert.Same(t, a, b)

	// differing on either field yields a distinct handle
	c := _host.getM("cache-test.example.com", "websocket")
	d := _host.getM("other.example.com", "")
	assert.NotSame(t, a, c)
	assert.NotSame(t, a, d)
}

func TestPromRequestsIncCachesAndCounts(t *testing.T) {
	r := httptest.NewRequest("GET", "http://count-test.example.com/x", nil)
	s := state.State{
		"namespace":   "ns",
		"ingress":     "ing",
		"serviceName": "svc",
		"serviceType": "ClusterIP",
	}
	r = r.WithContext(state.NewContext(r.Context(), s))
	start := time.Now()

	_promRequests.Inc(r, 200, start)
	_promRequests.Inc(r, 200, start)

	key := requestKey{
		host:        "count-test.example.com",
		namespace:   "ns",
		ingress:     "ing",
		serviceName: "svc",
		serviceType: "ClusterIP",
		method:      "GET",
		status:      200,
	}

	// the two 200 calls share one cache entry; a 404 adds a second
	_promRequests.Inc(r, 404, start)

	_promRequests.mu.RLock()
	rm200 := _promRequests.m[key]
	key.status = 404
	rm404 := _promRequests.m[key]
	_promRequests.mu.RUnlock()

	// both 200 calls resolved to one cached entry; 404 is a distinct one
	assert.NotNil(t, rm200)
	assert.NotNil(t, rm404)
	assert.NotSame(t, rm200, rm404)
}
