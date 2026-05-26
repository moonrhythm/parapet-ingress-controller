package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestHTTPTransport(t *testing.T) {
	t.Parallel()

	var called bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "HTTP/1.1", r.Proto)
		called = true
	}))
	defer ts.Close()

	tr := newHTTPTransport(newDialer().DialContext)
	r := httptest.NewRequest(http.MethodGet, ts.URL, nil)
	w, err := tr.RoundTrip(r)
	assert.NoError(t, err)
	assert.NotNil(t, w)
	assert.True(t, called)
}

func TestH2CTransport(t *testing.T) {
	t.Parallel()

	var called bool
	ts := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "HTTP/2.0", r.Proto)
		called = true
	}), &http2.Server{}))
	defer ts.Close()

	dialer := newDialer()
	tr := newH2CTransport(dialer.DialContext, newHTTPTransport(dialer.DialContext))
	r := httptest.NewRequest(http.MethodGet, ts.URL, nil)
	w, err := tr.RoundTrip(r)
	assert.NoError(t, err)
	assert.NotNil(t, w)
	assert.True(t, called)
}
