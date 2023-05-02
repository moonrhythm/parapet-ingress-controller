package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGateway(t *testing.T) {
	t.Parallel()

	lastCall := ""
	g := gateway{
		Default: mockTransport{
			func(r *http.Request) (*http.Response, error) {
				lastCall = "default"
				return nil, nil
			},
		},
		H2C: mockTransport{
			func(r *http.Request) (*http.Response, error) {
				lastCall = "h2c"
				return nil, nil
			},
		},
	}

	r := httptest.NewRequest("GET", "http://example.com", nil)
	g.RoundTrip(r)
	assert.Equal(t, "default", lastCall)

	r = httptest.NewRequest("GET", "h2c://example.com", nil)
	g.RoundTrip(r)
	assert.Equal(t, "h2c", lastCall)
}

type mockTransport struct {
	f func(r *http.Request) (*http.Response, error)
}

func (m mockTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return m.f(r)
}
