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

func TestBuildRoutes(t *testing.T) {
	var called string
	h := func(p string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			called = p
		}
	}

	routes := map[string]http.Handler{}
	routes["example.com/"] = h("example.com/")
	routes["example.com/path"] = h("example.com/path")
	routes["example.com/path/"] = h("example.com/path/")
	routes["example.com/path/path2"] = h("example.com/path/path2")

	mux := buildRoutes(routes)

	f := func(path string, expected string) {
		called = ""
		r := httptest.NewRequest(http.MethodGet, "http://"+path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		assert.Equal(t, expected, called)
	}
	f("example.com/", "example.com/")
	f("example.com/path", "example.com/path")
	f("example.com/path/test", "example.com/path/")
	f("example.com/path/path2", "example.com/path/path2")
	f("example.com/path/path2/path3", "example.com/path/")
}

func TestBuildRoutes_Duplicate(t *testing.T) {
	t.Parallel()

	routes := map[string]http.Handler{}
	routes["example.com/path"] = http.NotFoundHandler()
	routes["example.com/path"] = http.NotFoundHandler()
	var called bool
	routes["example.com/path2"] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	var mux *http.ServeMux
	assert.NotPanics(t, func() {
		mux = buildRoutes(routes)
	})
	r := httptest.NewRequest(http.MethodGet, "http://example.com/path2", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	assert.True(t, called)
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
