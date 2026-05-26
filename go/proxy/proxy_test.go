package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProxy(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		t.Parallel()

		var called bool
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer ts.Close()

		proxy := New()
		r := httptest.NewRequest(http.MethodGet, ts.URL, nil)
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, r)
		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "OK", w.Body.String())
	})
}

func TestIsRetryable(t *testing.T) {
	t.Parallel()

	assert.True(t, IsRetryable(errBadGateway))
	assert.True(t, IsRetryable(errServiceUnavailable))
}
