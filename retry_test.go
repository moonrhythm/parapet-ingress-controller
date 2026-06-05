package controller

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

// retryMiddleware must retry only on connection failures. An upstream that
// *responded* (even 502/503) has processed the request, so retrying it could
// duplicate side effects and amplify load on a failing backend.
func TestRetryMiddleware(t *testing.T) {
	t.Parallel()

	dialErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}

	serve := func(h http.Handler) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "http://svc/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	t.Run("retries a connection error up to maxRetry", func(t *testing.T) {
		var calls atomic.Int32
		w := serve(retryMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			calls.Add(1)
			panic(error(dialErr))
		})))
		assert.Equal(t, int32(5), calls.Load())
		assert.Equal(t, http.StatusBadGateway, w.Code)
	})

	t.Run("does NOT retry an upstream 503 response", func(t *testing.T) {
		var calls atomic.Int32
		w := serve(retryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		})))
		assert.Equal(t, int32(1), calls.Load(), "a responded 503 is served once, not retried")
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("a canceled context aborts the retry loop immediately", func(t *testing.T) {
		// Once the request context is canceled (client disconnected), the loop must
		// stop retrying — the ctx.Done() case must break the *loop*, not just the
		// select. The handler keeps emitting a retryable dial error, so a bare
		// `break` would burn through all maxRetry attempts; the labeled break stops
		// after the first.
		var calls atomic.Int32
		ctx, cancel := context.WithCancel(context.Background())
		h := retryMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			calls.Add(1)
			cancel() // disconnect mid-attempt
			panic(error(dialErr))
		}))
		r := httptest.NewRequest(http.MethodGet, "http://svc/", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		assert.Equal(t, int32(1), calls.Load(),
			"canceled context must abort the loop after one attempt, not retry")
		assert.Equal(t, http.StatusBadGateway, w.Code)
	})

	t.Run("does NOT retry a non-connection panic", func(t *testing.T) {
		var calls atomic.Int32
		w := serve(retryMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			calls.Add(1)
			panic(errors.New("boom"))
		})))
		assert.Equal(t, int32(1), calls.Load(), "non-retryable error served once")
		assert.Equal(t, http.StatusBadGateway, w.Code)
	})
}
