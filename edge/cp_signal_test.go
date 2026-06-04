package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newSignalCP(t *testing.T, h http.HandlerFunc) *CpClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cp, err := NewCpClient(srv.URL, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

// FetchCert must surface X-Parapet-CA-Id on the 200, the 304 (the STEADY-STATE carrier
// — almost every response is a 304), AND the 404 (a missing-cert sni still learns the
// target). A regression here silently disables fleet-wide proactive convergence.
func TestFetchCertCarriesCAIDOnEveryArm(t *testing.T) {
	cases := []struct {
		name string
		code int
		body string
	}{
		{"200", http.StatusOK, `{"chain_pem":"c","key_pem":"k"}`},
		{"304", http.StatusNotModified, ""},
		{"404", http.StatusNotFound, "no cert"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := newSignalCP(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Parapet-CA-Id", "target-123")
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			})
			res, err := cp.FetchCert("acme.com", "")
			if tc.code == http.StatusNotFound && err == nil {
				t.Error("404 should be an error")
			}
			if res.CAID != "target-123" {
				t.Errorf("%s: CAID = %q, want target-123 (the signal must ride this arm)", tc.name, res.CAID)
			}
		})
	}
}

func TestFetchTrustBundleCAID(t *testing.T) {
	cp := newSignalCP(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"generation":3,"ca_pem":"x","ca_id":"tb-abc"}`))
	})
	id, err := cp.FetchTrustBundleCAID()
	if err != nil {
		t.Fatal(err)
	}
	if id != "tb-abc" {
		t.Errorf("ca_id = %q, want tb-abc", id)
	}
}

func TestFetchEdgeCertRetryAfter(t *testing.T) {
	cp := newSignalCP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	res, err := cp.FetchEdgeCert([]byte("csr"))
	if err == nil {
		t.Fatal("503 should be an error")
	}
	if res.RetryAfter != 7*time.Second {
		t.Errorf("RetryAfter = %v, want 7s", res.RetryAfter)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("5"); got != 5*time.Second {
		t.Errorf("delta-seconds: %v, want 5s", got)
	}
	if got := parseRetryAfter(""); got != 0 {
		t.Errorf("empty: %v, want 0", got)
	}
	if got := parseRetryAfter("-3"); got != 0 {
		t.Errorf("negative: %v, want 0", got)
	}
	if got := parseRetryAfter("garbage"); got != 0 {
		t.Errorf("garbage: %v, want 0", got)
	}
	future := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(future); got <= 0 || got > 31*time.Second {
		t.Errorf("http-date: %v, want ~30s", got)
	}
}
