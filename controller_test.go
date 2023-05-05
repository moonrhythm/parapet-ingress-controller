package controller

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
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
