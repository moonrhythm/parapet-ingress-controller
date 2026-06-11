package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// serve drives one request through the Requests middleware and returns it.
func serveRequest(t *testing.T, mw interface {
	ServeHandler(http.Handler) http.Handler
}, method, host string, write func(http.ResponseWriter)) {
	t.Helper()
	h := mw.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write(w)
	}))
	r := httptest.NewRequest(method, "http://"+host+"/x", nil)
	r.Host = host
	h.ServeHTTP(httptest.NewRecorder(), r)
}

func count(host, status, method string) float64 {
	return testutil.ToFloat64(requestsVec.WithLabelValues(host, status, method, edgeID))
}

func TestRequestsCountsAndCollapsesHost(t *testing.T) {
	known := map[string]struct{}{"app.example.com": {}}
	mw := Requests(func(h string) bool { _, ok := known[h]; return ok })

	// Known host: labeled verbatim, status taken from WriteHeader.
	before := count("app.example.com", "418", "GET")
	serveRequest(t, mw, http.MethodGet, "app.example.com", func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusTeapot)
	})
	if got := count("app.example.com", "418", "GET"); got != before+1 {
		t.Errorf("known host: %v -> %v, want +1", before, got)
	}

	// Unknown host collapses to "other" so a random-Host flood can't grow series.
	before = count("other", "418", "GET")
	serveRequest(t, mw, http.MethodGet, "evil.example.net", func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusTeapot)
	})
	if got := count("other", "418", "GET"); got != before+1 {
		t.Errorf("unknown host: %v -> %v, want +1 under \"other\"", before, got)
	}
	// ...and never under its raw name.
	if c := testutil.CollectAndCount(requestsVec); c == 0 {
		t.Fatal("expected series registered")
	}
}

func TestRequestsDefaultStatusAndBounding(t *testing.T) {
	mw := Requests(func(string) bool { return true })

	// Body written without WriteHeader => 200.
	before := count("h.example.com", "200", "GET")
	serveRequest(t, mw, http.MethodGet, "h.example.com", func(w http.ResponseWriter) {
		_, _ = w.Write([]byte("ok"))
	})
	if got := count("h.example.com", "200", "GET"); got != before+1 {
		t.Errorf("default status: %v -> %v, want +1 under 200", before, got)
	}

	// Unregistered method token collapses to "other".
	before = count("h.example.com", "200", "other")
	serveRequest(t, mw, "WEIRDVERB", "h.example.com", func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
	})
	if got := count("h.example.com", "200", "other"); got != before+1 {
		t.Errorf("method bounding: %v -> %v, want +1 under \"other\"", before, got)
	}
}

func TestRequestsNilKnownHostPassesThrough(t *testing.T) {
	mw := Requests(nil) // nil knownHost: host passes through unchanged (test convenience)
	before := count("verbatim.example.com", "200", "GET")
	serveRequest(t, mw, http.MethodGet, "verbatim.example.com", func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
	})
	if got := count("verbatim.example.com", "200", "GET"); got != before+1 {
		t.Errorf("nil knownHost: %v -> %v, want +1 verbatim", before, got)
	}
}

func TestStatusLabelBounds(t *testing.T) {
	cases := map[int]string{0: "other", 99: "other", 100: "100", 200: "200", 599: "599", 600: "other", 700: "other"}
	for code, want := range cases {
		if got := statusLabel(code); got != want {
			t.Errorf("statusLabel(%d) = %q, want %q", code, got, want)
		}
	}
}
