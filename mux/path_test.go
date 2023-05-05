package mux

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathMux(t *testing.T) {
	t.Parallel()

	t.Run("Exact root match", func(t *testing.T) {
		m := pathMux{}
		var called bool
		m.AddExact("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		m.AddExact("/test", http.NotFoundHandler())
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		assert.True(t, called)
	})

	t.Run("Exact root not match", func(t *testing.T) {
		m := pathMux{}
		var called bool
		m.AddExact("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		m.AddExact("/test", http.NotFoundHandler())
		r := httptest.NewRequest(http.MethodGet, "/a", nil)
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		assert.False(t, called)
	})

	t.Run("Exact path match", func(t *testing.T) {
		m := pathMux{}
		var called bool
		m.AddExact("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		m.AddExact("/", http.NotFoundHandler())
		r := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		assert.True(t, called)
	})

	t.Run("Exact path not match", func(t *testing.T) {
		m := pathMux{}
		var called bool
		m.AddExact("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		m.AddExact("/", http.NotFoundHandler())
		r := httptest.NewRequest(http.MethodGet, "/about", nil)
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		assert.False(t, called)
	})

	t.Run("Prefix root match exact", func(t *testing.T) {
		m := pathMux{}
		var called bool
		m.AddPrefix("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		m.AddExact("/test", http.NotFoundHandler())
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		assert.True(t, called)
	})

	t.Run("Prefix root match prefix", func(t *testing.T) {
		m := pathMux{}
		var called bool
		m.AddPrefix("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		m.AddExact("/test", http.NotFoundHandler())
		r := httptest.NewRequest(http.MethodGet, "/about", nil)
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		assert.True(t, called)
	})

	t.Run("Prefix path match exact", func(t *testing.T) {
		t.Run("request without trailing slash", func(t *testing.T) {
			m := pathMux{}
			var called bool
			m.AddPrefix("/about", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			}))
			m.AddExact("/test", http.NotFoundHandler())

			r := httptest.NewRequest(http.MethodGet, "/about", nil)
			w := httptest.NewRecorder()
			m.ServeHTTP(w, r)
			assert.True(t, called)
		})

		t.Run("request with trailing slash", func(t *testing.T) {
			m := pathMux{}
			var called bool
			m.AddPrefix("/about", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			}))
			m.AddExact("/test", http.NotFoundHandler())

			r := httptest.NewRequest(http.MethodGet, "/about/", nil)
			w := httptest.NewRecorder()
			m.ServeHTTP(w, r)
			assert.True(t, called)
		})

		t.Run("add trailing and request without trailing slash", func(t *testing.T) {
			m := pathMux{}
			var called bool
			m.AddPrefix("/about/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			}))
			m.AddExact("/test", http.NotFoundHandler())

			r := httptest.NewRequest(http.MethodGet, "/about", nil)
			w := httptest.NewRecorder()
			m.ServeHTTP(w, r)
			assert.True(t, called)
		})

		t.Run("add trailing and request with trailing slash", func(t *testing.T) {
			m := pathMux{}
			var called bool
			m.AddPrefix("/about/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			}))
			m.AddExact("/test", http.NotFoundHandler())

			r := httptest.NewRequest(http.MethodGet, "/about/", nil)
			w := httptest.NewRecorder()
			m.ServeHTTP(w, r)
			assert.True(t, called)
		})
	})

	t.Run("Prefix path match prefix", func(t *testing.T) {
		m := pathMux{}
		var called bool
		m.AddPrefix("/about", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		m.AddExact("/test", http.NotFoundHandler())

		r := httptest.NewRequest(http.MethodGet, "/about/us", nil)
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		assert.True(t, called)
	})

	t.Run("Prefix path with trailing match prefix", func(t *testing.T) {
		m := pathMux{}
		var called bool
		m.AddPrefix("/about/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		m.AddExact("/test", http.NotFoundHandler())

		r := httptest.NewRequest(http.MethodGet, "/about/us", nil)
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		assert.True(t, called)
	})
}
