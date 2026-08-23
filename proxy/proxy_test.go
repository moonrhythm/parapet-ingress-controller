package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// TestErrorHandlerMarksBad: a post-connect failure that produces no HTTP
// response marks the target so RRLB can skip it. Retry stays dial-only — this
// request still 502s. An upstream that responded, or a client cancel/deadline,
// is not a mark signal.
func TestErrorHandlerMarksBad(t *testing.T) {
	t.Parallel()

	t.Run("accept then close marks the target", func(t *testing.T) {
		t.Parallel()

		addr := acceptAndClose(t)
		var marked []string
		p := New()
		p.OnDialError = func(a string) { marked = append(marked, a) }

		r := httptest.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadGateway, w.Code)
		assert.Equal(t, []string{addr}, marked)
	})

	t.Run("upstream 503 response is not marked", func(t *testing.T) {
		t.Parallel()

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("upstream-503"))
		}))
		defer ts.Close()

		var marked []string
		p := New()
		p.OnDialError = func(a string) { marked = append(marked, a) }

		r := httptest.NewRequest(http.MethodGet, ts.URL, nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Equal(t, "upstream-503", w.Body.String())
		assert.Empty(t, marked)
	})

	t.Run("client cancel is not marked", func(t *testing.T) {
		t.Parallel()

		received := make(chan struct{})
		ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			close(received)
			<-r.Context().Done()
		}))
		defer ts.Close()

		var marked []string
		p := New()
		p.OnDialError = func(a string) { marked = append(marked, a) }

		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			<-received
			cancel()
		}()
		r := httptest.NewRequest(http.MethodGet, ts.URL, nil).WithContext(ctx)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)

		assert.Equal(t, 499, w.Code)
		assert.Empty(t, marked)
	})

	t.Run("request deadline is not marked", func(t *testing.T) {
		t.Parallel()

		ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer ts.Close()

		var marked []string
		p := New()
		p.OnDialError = func(a string) { marked = append(marked, a) }

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		r := httptest.NewRequest(http.MethodGet, ts.URL, nil).WithContext(ctx)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadGateway, w.Code)
		assert.Empty(t, marked, "a client/request deadline is not evidence the pod is dead")
	})

	t.Run("dial refused panics and marks once", func(t *testing.T) {
		t.Parallel()

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()

		var marked []string
		p := New()
		p.OnDialError = func(a string) { marked = append(marked, a) }

		r := httptest.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
		w := httptest.NewRecorder()
		var recovered any
		func() {
			defer func() { recovered = recover() }()
			p.ServeHTTP(w, r)
		}()

		err, _ = recovered.(error)
		assert.Error(t, err)
		assert.True(t, IsRetryable(err), "dial failure must panic for retryMiddleware")
		assert.Equal(t, []string{addr}, marked, "dialer marks once; ErrorHandler panics before a second mark")
	})
}

func acceptAndClose(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().String()
}
