package metric

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/state"
)

// BenchmarkPromRequestsInc measures the steady-state (cache-hit) per-request
// cost of recording request metrics — the path every request takes.
func BenchmarkPromRequestsInc(b *testing.B) {
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	s := state.State{
		"namespace":   "default",
		"ingress":     "my-ingress",
		"serviceName": "my-service",
		"serviceType": "ClusterIP",
	}
	r = r.WithContext(state.NewContext(r.Context(), s))
	start := time.Now()

	// warm the cache so we measure the hot path, not the one-time miss
	_promRequests.Inc(r, 200, start)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_promRequests.Inc(r, 200, start)
	}
}

// BenchmarkHostGetM measures the steady-state (cache-hit) per-request cost of
// resolving the host active-requests gauge.
func BenchmarkHostGetM(b *testing.B) {
	_host.getM("example.com", "") // warm

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_host.getM("example.com", "")
	}
}
