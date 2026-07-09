package edge

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newWSHandshake builds a minimal client-side HTTP/1.1 WebSocket upgrade request.
func newWSHandshake(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://core.example"+path, nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	return r
}

// stubRT is an http.RoundTripper the tests inject into wsTunnel — the real
// not-supported error is unexported and needs a non-advertising h2 server, so the
// stub keeps the translation/fallback checks a unit test.
type stubRT struct {
	called bool
	resp   *http.Response
	err    error
}

func (s *stubRT) RoundTrip(r *http.Request) (*http.Response, error) {
	s.called = true
	if r.Body != nil {
		// Drain nothing but close so the pipe writer side unblocks on teardown.
		go func() { _, _ = io.Copy(io.Discard, r.Body) }()
	}
	return s.resp, s.err
}

// hijackRecorder (defined in cachestatus_test.go) is a hijackable
// ResponseRecorder so canHijack passes; Hijack is only reached on the 200 path,
// which these unit tests do not exercise.

func TestWSTunnel_TranslateCloneShape(t *testing.T) {
	tun := &wsTunnel{scheme: "https", addr: "core:443"}
	r := newWSHandshake("/chat?x=1")
	r.Header.Set("Sec-WebSocket-Protocol", "chat")
	r.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate")

	pr, pw := io.Pipe()
	defer pw.Close()
	c := tun.translate(context.Background(), r, pr)

	// clone is the extended-CONNECT shape (RFC 8441 §4–5)
	assert.Equal(t, http.MethodConnect, c.Method)
	assert.Equal(t, "websocket", c.Header.Get(":protocol"))
	assert.Equal(t, "https", c.URL.Scheme)
	assert.Equal(t, "core:443", c.URL.Host)
	assert.Equal(t, "/chat", c.URL.Path)
	assert.Equal(t, "x=1", c.URL.RawQuery)
	assert.Empty(t, c.Header.Get("Connection"), "Connection dropped (illegal on h2)")
	assert.Empty(t, c.Header.Get("Upgrade"), "Upgrade dropped (illegal on h2)")
	assert.Empty(t, c.Header.Get("Sec-WebSocket-Key"), "key does not exist on h2")
	assert.Equal(t, "chat", c.Header.Get("Sec-WebSocket-Protocol"), "subprotocol rides through")
	assert.Equal(t, "permessage-deflate", c.Header.Get("Sec-WebSocket-Extensions"), "extensions ride through")
	assert.Equal(t, "13", c.Header.Get("Sec-WebSocket-Version"), "version rides through")

	// original is untouched so the caller can still fall back with it
	assert.Equal(t, http.MethodGet, r.Method)
	assert.Equal(t, "Upgrade", r.Header.Get("Connection"))
	assert.Equal(t, "websocket", r.Header.Get("Upgrade"))
	assert.NotEmpty(t, r.Header.Get("Sec-WebSocket-Key"))
	assert.Empty(t, r.Header.Get(":protocol"))
}

func TestWSTunnel_NotSupportedFallsBack(t *testing.T) {
	rt := &stubRT{err: errors.New("net/http: extended connect not supported by peer")}
	tun := &wsTunnel{tr: rt, scheme: "http", addr: "core:80"}

	r := newWSHandshake("/chat")
	w := &hijackRecorder{ResponseRecorder: httptest.NewRecorder()}

	handled := tun.serve(w, r)
	assert.False(t, handled, "not-supported must fall back to the h1 path")
	assert.True(t, rt.called, "the tunnel was attempted")
	assert.Equal(t, 200, w.Code, "no response written to the client on fallback")

	// original request preserved for the fallback
	assert.Equal(t, http.MethodGet, r.Method)
	assert.Equal(t, "websocket", r.Header.Get("Upgrade"))
	assert.NotEmpty(t, r.Header.Get("Sec-WebSocket-Key"))
}

// A generic (non not-supported) pre-commit RoundTrip error also falls back —
// a clean ALPN/dial failure from an old core must not 502 the client.
func TestWSTunnel_GenericErrorFallsBack(t *testing.T) {
	rt := &stubRT{err: errors.New("dial tcp: connection refused")}
	tun := &wsTunnel{tr: rt, scheme: "http", addr: "core:80"}

	r := newWSHandshake("/chat")
	w := &hijackRecorder{ResponseRecorder: httptest.NewRecorder()}

	assert.False(t, tun.serve(w, r))
	assert.True(t, rt.called)
}

func TestWSTunnel_BadHandshake(t *testing.T) {
	tun := &wsTunnel{tr: &stubRT{}, scheme: "http", addr: "core:80"}

	t.Run("missing key", func(t *testing.T) {
		r := newWSHandshake("/chat")
		r.Header.Del("Sec-WebSocket-Key")
		w := httptest.NewRecorder()
		require.True(t, tun.serve(w, r))
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("non-GET", func(t *testing.T) {
		r := newWSHandshake("/chat")
		r.Method = http.MethodPost
		w := httptest.NewRecorder()
		require.True(t, tun.serve(w, r))
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// A non-hijackable ResponseWriter (never the edge's h1 listener) falls back
// without committing anything to the client.
func TestWSTunnel_NonHijackableFallsBack(t *testing.T) {
	rt := &stubRT{}
	tun := &wsTunnel{tr: rt, scheme: "http", addr: "core:80"}
	r := newWSHandshake("/chat")
	w := httptest.NewRecorder() // ResponseRecorder is not an http.Hijacker

	assert.False(t, tun.serve(w, r))
	assert.False(t, rt.called, "must not attempt the tunnel when it cannot hijack")
}

func TestIsWebSocketUpgrade(t *testing.T) {
	cases := []struct {
		upgrade string
		want    bool
	}{
		{"websocket", true},
		{"WebSocket", true},
		{"WEBSOCKET", true},
		{"h2c", false},
		{"", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "http://x/", nil)
		if c.upgrade != "" {
			r.Header.Set("Upgrade", c.upgrade)
		}
		assert.Equalf(t, c.want, isWebSocketUpgrade(r), "upgrade=%q", c.upgrade)
	}
}
