package ratelimitrule_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/moonrhythm/parapet-ingress-controller/ratelimitrule"
)

// benchServe drives the allowed fast path: the writer is never written to and
// the request is reused, so allocations measured are the limiter's own
// per-request cost (key resolution + strategy take + observe), not harness
// noise. rate is huge so b.N never exhausts the budget.
func benchServe(b *testing.B, lim ratelimitrule.Limit, hdr map[string]string) {
	b.Helper()

	l := &ratelimitrule.Limiter{}
	lim.ID = "bench"
	lim.Rate = 1 << 30
	lim.Window = "1h"
	if err := l.SetLimits([]ratelimitrule.Limit{lim}); err != nil {
		b.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://bench.example.com/", nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Serve(w, r, next)
	}
}

func BenchmarkServeIPKeyFixed(b *testing.B) {
	benchServe(b, ratelimitrule.Limit{}, map[string]string{"X-Real-Ip": "203.0.113.7"})
}

func BenchmarkServeIPKeyFixedV6(b *testing.B) {
	benchServe(b, ratelimitrule.Limit{}, map[string]string{"X-Real-Ip": "2001:db8::1"})
}

func BenchmarkServeIPKeySliding(b *testing.B) {
	benchServe(b, ratelimitrule.Limit{Algorithm: "sliding"}, map[string]string{"X-Real-Ip": "203.0.113.7"})
}

func BenchmarkServeIPHostKey(b *testing.B) {
	benchServe(b, ratelimitrule.Limit{Key: ratelimitrule.Keys{"ip", "host"}},
		map[string]string{"X-Real-Ip": "203.0.113.7"})
}

func BenchmarkServeHeaderKey(b *testing.B) {
	benchServe(b, ratelimitrule.Limit{Key: ratelimitrule.Keys{"header:x-api-key"}},
		map[string]string{"X-Api-Key": "bench-token"})
}

func BenchmarkServeIPKeyWithExclude(b *testing.B) {
	// Non-matching exclude list: the per-request cost is parse + miss on every
	// prefix, the worst case for the exclude path.
	benchServe(b, ratelimitrule.Limit{Exclude: []string{"10.0.0.0/8", "192.168.0.0/16", "fc00::/7"}},
		map[string]string{"X-Real-Ip": "203.0.113.7"})
}
