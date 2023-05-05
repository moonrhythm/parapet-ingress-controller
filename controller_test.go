package controller

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

// verify http.ServeMux behavior
func TestMux(t *testing.T) {
	t.Parallel()

	t.Run("Prefix Host", func(t *testing.T) {
		t.Run("Match Exact", func(t *testing.T) {
			mux := http.NewServeMux()
			var called bool
			mux.HandleFunc("example.com/", func(w http.ResponseWriter, r *http.Request) {
				called = true
			})
			r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			assert.True(t, called)
		})

		t.Run("Match Prefix", func(t *testing.T) {
			mux := http.NewServeMux()
			var called bool
			mux.HandleFunc("example.com/", func(w http.ResponseWriter, r *http.Request) {
				called = true
			})
			r := httptest.NewRequest(http.MethodGet, "http://example.com/test/path", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			assert.True(t, called)
		})
	})

	t.Run("Prefix Path", func(t *testing.T) {
		t.Run("Not Match Exact without trailing", func(t *testing.T) {
			mux := http.NewServeMux()
			var called bool
			mux.HandleFunc("example.com/path/", func(w http.ResponseWriter, r *http.Request) {
				called = true
			})
			r := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			assert.False(t, called)
		})

		t.Run("Match Exact with trailing", func(t *testing.T) {
			mux := http.NewServeMux()
			var called bool
			mux.HandleFunc("example.com/path/", func(w http.ResponseWriter, r *http.Request) {
				called = true
			})
			r := httptest.NewRequest(http.MethodGet, "http://example.com/path/", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			assert.True(t, called)
		})
	})

	t.Run("Exact Path", func(t *testing.T) {
		t.Run("Match Exact", func(t *testing.T) {
			mux := http.NewServeMux()
			var called bool
			mux.HandleFunc("example.com/path", func(w http.ResponseWriter, r *http.Request) {
				called = true
			})
			r := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			assert.True(t, called)
		})

		t.Run("Not Match trailing", func(t *testing.T) {
			mux := http.NewServeMux()
			var called bool
			mux.HandleFunc("example.com/path", func(w http.ResponseWriter, r *http.Request) {
				called = true
			})
			r := httptest.NewRequest(http.MethodGet, "http://example.com/path/", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			assert.False(t, called)
		})
	})
}

func TestEndpointToRRLB(t *testing.T) {
	t.Parallel()

	t.Run("Empty", func(t *testing.T) {
		ep := v1.Endpoints{}
		lb := endpointToRRLB(&ep)
		assert.Nil(t, lb)
	})

	t.Run("Single Subset", func(t *testing.T) {
		ep := v1.Endpoints{
			Subsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{IP: "192.168.0.1"},
						{IP: "192.168.0.2"},
						{IP: "192.168.0.3"},
					},
				},
			},
		}
		lb := endpointToRRLB(&ep)
		if assert.NotNil(t, lb) {
			assert.EqualValues(t, []string{"192.168.0.1", "192.168.0.2", "192.168.0.3"}, lb.IPs)
		}
	})

	t.Run("Multiple Subsets", func(t *testing.T) {
		ep := v1.Endpoints{
			Subsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{IP: "192.168.0.1"},
						{IP: "192.168.0.2"},
					},
				},
				{
					Addresses: []v1.EndpointAddress{
						{IP: "192.168.0.3"},
					},
				},
			},
		}
		lb := endpointToRRLB(&ep)
		if assert.NotNil(t, lb) {
			assert.EqualValues(t, []string{"192.168.0.1", "192.168.0.2", "192.168.0.3"}, lb.IPs)
		}
	})
}
