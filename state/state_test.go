package state_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/moonrhythm/parapet"
	"github.com/stretchr/testify/assert"

	. "github.com/moonrhythm/parapet-ingress-controller/state"
)

func TestState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	s := State{}
	s["a"] = "1"

	ctx = NewContext(ctx, s)
	s["b"] = "2"

	ps := Get(ctx)
	ps["c"] = "3"

	assert.Equal(t, "1", s["a"])
	assert.Equal(t, "2", s["b"])
	assert.Equal(t, "3", s["c"])
	assert.Equal(t, "1", ps["a"])
	assert.Equal(t, "2", ps["b"])
	assert.Equal(t, "3", ps["c"])
}

func TestGet(t *testing.T) {
	t.Parallel()

	// get always return non nil State
	s := Get(context.Background())
	assert.NotNil(t, s)
}

func TestMiddleware(t *testing.T) {
	t.Parallel()

	var called bool
	var m parapet.Middlewares
	m.Use(Middleware())
	m.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s := Get(r.Context())
			s["a"] = "1"
			h.ServeHTTP(w, r)
			assert.Equal(t, "2", s["b"])
		})
	}))
	h := m.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := Get(r.Context())
		assert.Equal(t, "1", s["a"])
		s["b"] = "2"
		called = true
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.True(t, called)
}
