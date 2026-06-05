package metric

import (
	"net/http/httptest"
	"strconv"
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
	e := _host.getM("cache-test.example.com", "sse")
	assert.NotSame(t, a, c)
	assert.NotSame(t, a, d)
	assert.NotSame(t, a, e)
}

func TestMethodLabel(t *testing.T) {
	// registered methods pass through unchanged
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE"} {
		assert.Equal(t, m, methodLabel(m))
	}
	// anything else collapses to the bounded sentinel (case-sensitive: lower-case
	// and arbitrary tokens are non-standard)
	assert.Equal(t, "other", methodLabel(""))
	assert.Equal(t, "other", methodLabel("get"))
	assert.Equal(t, "other", methodLabel("FOOBAR"))
	assert.Equal(t, "other", methodLabel("PROPFIND"))
}

func TestMethodLabelBoundsRequestCardinality(t *testing.T) {
	// A client can send unbounded distinct (but syntactically valid) HTTP method
	// tokens to a host the router serves. Without methodLabel, each one mints a
	// new handle-cache entry and a permanent Prometheus series. methodLabel must
	// collapse them all to one "other" series per (host, status).
	const host = "method-card-test.example.com"
	s := state.State{
		"namespace":   "ns",
		"ingress":     "ing",
		"serviceName": "svc",
		"serviceType": "ClusterIP",
	}

	countEntries := func() int {
		n := 0
		_promRequests.cache.mu.RLock()
		for k := range _promRequests.cache.m {
			if k.host == host {
				n++
			}
		}
		_promRequests.cache.mu.RUnlock()
		return n
	}

	start := time.Now()
	for i := 0; i < 500; i++ {
		// httptest.NewRequest parses the request line through http.ReadRequest, so
		// these go through the same method-validation path a real client hits.
		method := "M" + strconv.Itoa(i)
		r := httptest.NewRequest(method, "http://"+host+"/x", nil)
		r = r.WithContext(state.NewContext(r.Context(), s))
		_promRequests.Inc(r, 200, start)
	}

	assert.Equal(t, 1, countEntries(),
		"500 distinct method tokens must collapse to a single 'other' series per (host,status)")
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

	_promRequests.cache.mu.RLock()
	rm200 := _promRequests.cache.m[key]
	key.status = 404
	rm404 := _promRequests.cache.m[key]
	_promRequests.cache.mu.RUnlock()

	// both 200 calls resolved to one cached entry; 404 is a distinct one
	assert.NotNil(t, rm200)
	assert.NotNil(t, rm404)
	assert.NotSame(t, rm200, rm404)
}
