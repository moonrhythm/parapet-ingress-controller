package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// countingRT wraps a RoundTripper and counts how many times it's invoked.
type countingRT struct {
	inner http.RoundTripper
	n     int
}

func (c *countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n++
	return c.inner.RoundTrip(r)
}

// rtFunc is a stub RoundTripper.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newAutoH2C(h2cRT, fallback http.RoundTripper) *autoH2CTransport {
	return &autoH2CTransport{h2c: h2cRT, fallback: fallback}
}

func (t *autoH2CTransport) cachedLen() int {
	n := 0
	t.bad.Range(func(_, _ any) bool { n++; return true })
	return n
}

// HTTP/1.1-only upstream: the first request probes h2c, fails, falls back to
// HTTP/1.1, and remembers the upstream so the second request skips the probe.
func TestAutoH2C_FallbackAndCache(t *testing.T) {
	t.Parallel()

	var (
		mu     sync.Mutex
		protos []string
	)
	// Force an HTTP/1.1-only upstream: Go's stdlib server otherwise auto-negotiates
	// h2c, which would defeat the point of probing for a fallback. The failed h2c
	// probe makes the server mis-parse the "PRI * HTTP/2.0" preface as a PRI
	// request, so only record the real GETs.
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			return
		}
		mu.Lock()
		protos = append(protos, r.Proto)
		mu.Unlock()
	}))
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	ts.Config.Protocols = &protocols
	ts.Start()
	defer ts.Close()

	dialer := newDialer()
	httpTr := newHTTPTransport(dialer.DialContext)
	h2cRT := &countingRT{inner: newH2CTransport(dialer.DialContext, httpTr)}
	tr := newAutoH2C(h2cRT, httpTr)

	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodGet, ts.URL, nil)
		resp, err := tr.RoundTrip(r)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// both requests served over HTTP/1.1
	require.Len(t, protos, 2)
	assert.Equal(t, "HTTP/1.1", protos[0])
	assert.Equal(t, "HTTP/1.1", protos[1])
	// h2c probed only once (second request hit the negative cache)
	assert.Equal(t, 1, h2cRT.n)
	assert.Equal(t, 1, tr.cachedLen())
}

// h2c upstream: the request succeeds over HTTP/2 and nothing is cached.
func TestAutoH2C_H2CSuccessNotCached(t *testing.T) {
	t.Parallel()

	var proto string
	ts := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
	}), &http2.Server{}))
	defer ts.Close()

	dialer := newDialer()
	httpTr := newHTTPTransport(dialer.DialContext)
	tr := newAutoH2C(newH2CTransport(dialer.DialContext, httpTr), httpTr)

	r := httptest.NewRequest(http.MethodGet, ts.URL, nil)
	resp, err := tr.RoundTrip(r)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "HTTP/2.0", proto)
	assert.Equal(t, 0, tr.cachedLen())
}

// Upgrade (WebSocket) requests must go straight to HTTP/1.1 — never probed, never cached.
func TestAutoH2C_UpgradeSkipsProbe(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	dialer := newDialer()
	httpTr := newHTTPTransport(dialer.DialContext)
	h2cRT := &countingRT{inner: newH2CTransport(dialer.DialContext, httpTr)}
	tr := newAutoH2C(h2cRT, httpTr)

	r := httptest.NewRequest(http.MethodGet, ts.URL, nil)
	r.Header.Set("Upgrade", "websocket")
	resp, err := tr.RoundTrip(r)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, 0, h2cRT.n)
	assert.Equal(t, 0, tr.cachedLen())
}

// A dial error means the pod is down, not that it lacks h2c: propagate it and
// don't poison the cache.
func TestAutoH2C_DialErrorNotCached(t *testing.T) {
	t.Parallel()

	dialErr := &net.OpError{Op: "dial", Err: io.EOF}
	h2cRT := rtFunc(func(*http.Request) (*http.Response, error) { return nil, dialErr })
	var fallbackCalled bool
	fallback := rtFunc(func(*http.Request) (*http.Response, error) {
		fallbackCalled = true
		return nil, nil
	})
	tr := newAutoH2C(h2cRT, fallback)

	r := httptest.NewRequest(http.MethodGet, "http://10.0.0.1:8080", nil)
	_, err := tr.RoundTrip(r)
	assert.ErrorIs(t, err, dialErr)
	assert.False(t, fallbackCalled, "dial error must not fall back")
	assert.Equal(t, 0, tr.cachedLen(), "dial error must not be cached")
}

// A non-dial h2c error with an unread body marks the upstream and replays over HTTP/1.1.
func TestAutoH2C_ProtocolErrorFallsBack(t *testing.T) {
	t.Parallel()

	h2cRT := rtFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF // not a dial error
	})
	var fallbackCalled bool
	fallback := rtFunc(func(r *http.Request) (*http.Response, error) {
		fallbackCalled = true
		assert.Equal(t, "http", r.URL.Scheme)
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	tr := newAutoH2C(h2cRT, fallback)

	r := httptest.NewRequest(http.MethodGet, "http://10.0.0.1:8080", nil)
	resp, err := tr.RoundTrip(r)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, fallbackCalled)
	assert.Equal(t, 1, tr.cachedLen())
}

// If the body was already read during the h2c attempt, a replay is unsafe: the
// error is surfaced and the upstream is not cached.
func TestAutoH2C_BodyReadNoReplay(t *testing.T) {
	t.Parallel()

	h2cRT := rtFunc(func(r *http.Request) (*http.Response, error) {
		io.ReadAll(r.Body) // consume the body, then fail
		return nil, io.ErrUnexpectedEOF
	})
	var fallbackCalled bool
	fallback := rtFunc(func(*http.Request) (*http.Response, error) {
		fallbackCalled = true
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	tr := newAutoH2C(h2cRT, fallback)

	r := httptest.NewRequest(http.MethodPost, "http://10.0.0.1:8080", strings.NewReader("payload"))
	_, err := tr.RoundTrip(r)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.False(t, fallbackCalled, "must not replay a consumed body")
	assert.Equal(t, 0, tr.cachedLen())
}

// reset forgets every remembered upstream so they are re-probed.
func TestAutoH2C_Reset(t *testing.T) {
	t.Parallel()

	h2cRT := rtFunc(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF })
	fallback := rtFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	tr := newAutoH2C(h2cRT, fallback)

	r := httptest.NewRequest(http.MethodGet, "http://10.0.0.1:8080", nil)
	_, err := tr.RoundTrip(r)
	require.NoError(t, err)
	require.Equal(t, 1, tr.cachedLen())

	tr.reset()
	assert.Equal(t, 0, tr.cachedLen())
}
