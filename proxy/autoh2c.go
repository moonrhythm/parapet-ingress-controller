package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/moonrhythm/parapet/pkg/header"

	"github.com/moonrhythm/parapet-ingress-controller/state"
)

// autoH2CTransport speculatively tries h2c (HTTP/2 cleartext) for plain-http
// upstreams and falls back to HTTP/1.1 when the upstream doesn't speak HTTP/2.
// Upstreams that fail the h2c probe are remembered (per-Service, keyed via the
// request state) so subsequent requests skip the probe and go straight to
// HTTP/1.1. The negative cache is cleared on route reload (see Proxy.ResetH2C).
type autoH2CTransport struct {
	h2c      http.RoundTripper // *h2cTransport — HTTP/2 cleartext
	fallback http.RoundTripper // *http.Transport — HTTP/1.1
	bad      sync.Map          // upstream key (string) -> struct{}{}
}

func (t *autoH2CTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	key := upstreamKey(r)

	// Known HTTP/1.1-only upstream — don't probe again.
	if _, ok := t.bad.Load(key); ok {
		return t.fallback.RoundTrip(r)
	}

	// WebSocket / Upgrade requests can only be tunneled over HTTP/1.1
	// (httputil.ReverseProxy has no RFC 8441 HTTP/2 path), so route them
	// straight to the fallback. Their outcome says nothing about the
	// Service's plain-h2c support, so they are never probed or cached.
	if header.Exists(r.Header, header.Upgrade) {
		return t.fallback.RoundTrip(r)
	}

	// Falling back means re-sending the request on a second connection, which
	// is only safe if the body hasn't been read yet. A non-HTTP/2 peer fails
	// during the connection preface — before the body is read — so this guard
	// normally holds; we track it explicitly to stay safe.
	var bt *bodyTracker
	if r.Body != nil && r.Body != http.NoBody {
		bt = &bodyTracker{ReadCloser: r.Body}
		r.Body = bt
	}

	resp, err := t.h2c.RoundTrip(r)
	if err == nil {
		return resp, nil
	}

	// A dial error means the pod is down, not that it lacks h2c support: leave
	// the cache untouched and propagate so ErrorHandler / retryMiddleware can
	// handle it like any other connection failure.
	if isDialError(err) {
		return nil, err
	}

	// Any other error with the body still intact is treated as "no HTTP/2": mark
	// the upstream and replay over HTTP/1.1.
	if bt == nil || !bt.read {
		t.bad.Store(key, struct{}{})
		slog.Info("proxy: upstream does not support h2c, falling back to http/1.1",
			"upstream", key, "error", err)
		if bt != nil {
			r.Body = bt.ReadCloser
		}
		r.URL.Scheme = "http"
		return t.fallback.RoundTrip(r)
	}

	// Body already (partially) sent — replay isn't safe, surface the error.
	return nil, err
}

// reset drops every remembered upstream so they are re-probed.
func (t *autoH2CTransport) reset() {
	t.bad.Range(func(k, _ any) bool {
		t.bad.Delete(k)
		return true
	})
}

// upstreamKey identifies the upstream for the negative cache. It prefers the
// stable per-Service key stamped into the request state by the controller, and
// falls back to the dialed host:port when absent.
func upstreamKey(r *http.Request) string {
	if k := state.Get(r.Context())["upstreamKey"]; k != "" {
		return k
	}
	return r.URL.Host
}

// bodyTracker records whether anything has read the request body, so the
// auto-h2c fallback knows when a replay is still safe.
type bodyTracker struct {
	io.ReadCloser
	read bool
}

func (b *bodyTracker) Read(p []byte) (int, error) {
	b.read = true
	return b.ReadCloser.Read(p)
}
