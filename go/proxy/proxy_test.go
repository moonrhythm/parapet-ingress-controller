package proxy

import (
	"context"
	"errors"
	"net"
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

	t.Run("upstream 5xx passes through unchanged", func(t *testing.T) {
		t.Parallel()

		// An upstream that responds — even 503 — has processed the request, so its
		// response (status + body) reaches the client verbatim and the upstream is
		// hit exactly once. The proxy no longer rewrites it into an error to retry.
		var calls int
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("upstream-503"))
		}))
		defer ts.Close()

		proxy := New()
		r := httptest.NewRequest(http.MethodGet, ts.URL, nil)
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, r)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Equal(t, "upstream-503", w.Body.String())
		assert.Equal(t, 1, calls)
	})
}

func TestIsRetryable(t *testing.T) {
	t.Parallel()

	// Only connection failures are retryable.
	assert.True(t, IsRetryable(&net.OpError{Op: "dial", Err: errors.New("connection refused")}))
	assert.True(t, IsRetryable(context.DeadlineExceeded))

	// An upstream that responded (even 5xx) has processed the request — not a
	// connection error, so not retryable. Neither is a mid-flight (non-dial)
	// transport error or nil.
	assert.False(t, IsRetryable(errors.New("upstream returned 503")))
	assert.False(t, IsRetryable(&net.OpError{Op: "read", Err: errors.New("connection reset")}))
	assert.False(t, IsRetryable(nil))
}
