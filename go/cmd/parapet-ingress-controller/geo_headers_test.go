package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestForwardGeoHeaders(t *testing.T) {
	t.Parallel()

	// run sends one request through the middleware and returns the request as the
	// downstream handler saw it (i.e. what would be proxied upstream).
	run := func(country func(*http.Request) string, asn func(*http.Request) int64, setup func(*http.Request)) *http.Request {
		var got *http.Request
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r })
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if setup != nil {
			setup(r)
		}
		forwardGeoHeaders(country, asn).ServeHandler(next).ServeHTTP(httptest.NewRecorder(), r)
		return got
	}

	// Both resolvers active: headers set authoritatively, overwriting any
	// client-supplied (spoofed) values.
	r := run(
		func(*http.Request) string { return "TH" },
		func(*http.Request) int64 { return 13335 },
		func(r *http.Request) {
			r.Header.Set("X-Forwarded-Country", "US") // spoofed
			r.Header.Set("X-Forwarded-ASN", "1")      // spoofed
		},
	)
	assert.Equal(t, "TH", r.Header.Get("X-Forwarded-Country"))
	assert.Equal(t, "13335", r.Header.Get("X-Forwarded-ASN"))

	// Unresolved sentinels ("XX" / 0) are still forwarded.
	r = run(
		func(*http.Request) string { return "XX" },
		func(*http.Request) int64 { return 0 },
		nil,
	)
	assert.Equal(t, "XX", r.Header.Get("X-Forwarded-Country"))
	assert.Equal(t, "0", r.Header.Get("X-Forwarded-ASN"))

	// nil resolvers: the proxy leaves the headers untouched.
	r = run(nil, nil, func(r *http.Request) {
		r.Header.Set("X-Forwarded-Country", "US")
	})
	assert.Equal(t, "US", r.Header.Get("X-Forwarded-Country"))
	assert.Empty(t, r.Header.Get("X-Forwarded-ASN"))
}
