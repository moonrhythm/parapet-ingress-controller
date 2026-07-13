package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/moonrhythm/parapet-ingress-controller/wafclaim"
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

	t.Run("strips the WAF claim header upstream", func(t *testing.T) {
		t.Parallel()

		// The claim header is the edge→core wire contract: the core consumes it
		// in-process (the WAF_VALIDATED_PROXY skip) and must never forward it to
		// a backend — validated or not, WAF on or off.
		var claimSeen, otherSeen string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claimSeen = r.Header.Get(wafclaim.Header)
			otherSeen = r.Header.Get("X-Other")
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		proxy := New()
		r := httptest.NewRequest(http.MethodGet, ts.URL, nil)
		r.Header.Set(wafclaim.Header, "7")
		r.Header.Set("X-Other", "kept")
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, r)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, claimSeen, "the claim header must not reach the upstream backend")
		assert.Equal(t, "kept", otherSeen, "other headers pass through")
		assert.Equal(t, "7", r.Header.Get(wafclaim.Header),
			"the in-chain request is untouched (Director mutates the outbound clone)")
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

	// Only a dial failure (no connection established, request never sent) is
	// retryable — including one that timed out on the ctx deadline mid-dial.
	assert.True(t, IsRetryable(&net.OpError{Op: "dial", Err: errors.New("connection refused")}))
	assert.True(t, IsRetryable(&net.OpError{Op: "dial", Err: context.DeadlineExceeded}))

	// Once a connection is established, any failure is never retried — even
	// one that unwraps to context.DeadlineExceeded (e.g. hit while awaiting
	// response headers) — because the upstream may already have received the
	// request. Also not retryable: an upstream that responded (even 5xx), a
	// non-dial (e.g. "read") transport error, and nil.
	assert.False(t, IsRetryable(context.DeadlineExceeded))
	assert.False(t, IsRetryable(&net.OpError{Op: "read", Err: context.DeadlineExceeded}))
	assert.False(t, IsRetryable(errors.New("upstream returned 503")))
	assert.False(t, IsRetryable(&net.OpError{Op: "read", Err: errors.New("connection reset")}))
	assert.False(t, IsRetryable(nil))
}
