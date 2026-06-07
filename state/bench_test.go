package state

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// benchMiddleware drives a request through state.Middleware with a handler that
// writes the typical per-request state keys, for both logging configs. The
// log-disabled path should skip the per-key logger copy entirely.
func benchMiddleware(b *testing.B, logEnabled bool) {
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s := Get(r.Context())
		s["serviceName"] = "svc"
		s["serviceType"] = "ClusterIP"
		s["namespace"] = "ns"
		s["ingress"] = "ing"
		s["serviceTarget"] = "10.0.0.1:8080"
	})
	mw := Middleware(logEnabled).ServeHandler(inner)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mw.ServeHTTP(w, r)
	}
}

func BenchmarkStateMiddleware_LogDisabled(b *testing.B) { benchMiddleware(b, false) }
func BenchmarkStateMiddleware_LogEnabled(b *testing.B)  { benchMiddleware(b, true) }
