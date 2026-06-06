package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// countingRT wraps a RoundTripper and counts how many times it's invoked.
type countingRT struct {
	inner http.RoundTripper
	n     int32
}

func (c *countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	atomic.AddInt32(&c.n, 1)
	return c.inner.RoundTrip(r)
}

func (c *countingRT) calls() int { return int(atomic.LoadInt32(&c.n)) }

// rtFunc is a stub RoundTripper.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newAutoH2C(h2cRT, fallback http.RoundTripper) *autoH2CTransport {
	return newAutoH2CTransport(h2cRT, fallback, time.Minute)
}

func (t *autoH2CTransport) cachedLen() int {
	n := 0
	t.entries.Range(func(_, _ any) bool { n++; return true })
	return n
}

func (t *autoH2CTransport) rawEntry(key string) (h2cEntry, bool) {
	v, ok := t.entries.Load(key)
	if !ok {
		return h2cEntry{}, false
	}
	return v.(h2cEntry), true
}

// HTTP/1.1-only upstream: the first request probes h2c, fails, falls back to
// HTTP/1.1, and caches the negative verdict so the second request skips the probe.
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

	require.Len(t, protos, 2)
	assert.Equal(t, "HTTP/1.1", protos[0])
	assert.Equal(t, "HTTP/1.1", protos[1])
	// h2c probed only once (second request took the cached fast path)
	assert.Equal(t, 1, h2cRT.calls())
	e, ok := tr.rawEntry(ts.URL[len("http://"):])
	require.True(t, ok)
	assert.False(t, e.h2c, "negative verdict cached")
}

// End-to-end against a REAL HTTP/1.1 server with a POST body. Because the request
// carries a body it is never probed over h2c — it goes straight to HTTP/1.1 with its
// payload intact. This is the regression guard for the
// "http2: frame too large ... looked like an HTTP/1.1 header" error, which only arose
// when the h2c client streamed a body to a non-HTTP/2 peer.
func TestAutoH2C_RealServerPostBodyFallsBack(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		gotProto string
		gotBody  string
	)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotProto = r.Proto
		gotBody = string(b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	ts.Config.Protocols = &protocols
	ts.Start()
	defer ts.Close()

	dialer := newDialer()
	httpTr := newHTTPTransport(dialer.DialContext)
	tr := newAutoH2C(newH2CTransport(dialer.DialContext, httpTr), httpTr)

	r := httptest.NewRequest(http.MethodPost, ts.URL, strings.NewReader("hello-body"))
	resp, err := tr.RoundTrip(r)
	require.NoError(t, err, "POST must reach HTTP/1.1, not surface the h2c frame error")
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 0, tr.cachedLen(), "a bodied request neither probes nor caches")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "HTTP/1.1", gotProto)
	assert.Equal(t, "hello-body", gotBody, "the upstream received the full body")
}

// h2c upstream: the request succeeds over HTTP/2 and the positive verdict is cached.
func TestAutoH2C_H2CSuccessCachedPositive(t *testing.T) {
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

	e, ok := tr.rawEntry(ts.URL[len("http://"):])
	require.True(t, ok)
	assert.True(t, e.h2c, "positive verdict cached")
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

	assert.Equal(t, 0, h2cRT.calls())
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

// A non-dial h2c error with an unread body caches the negative verdict and
// replays over HTTP/1.1.
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
	e, ok := tr.rawEntry("10.0.0.1:8080")
	require.True(t, ok)
	assert.False(t, e.h2c)
}

// A body-carrying request to an as-yet-unknown upstream is NOT probed: it goes
// straight to HTTP/1.1 with its body untouched, and nothing is cached (a later
// bodyless request establishes the verdict). This is what avoids the
// "http2: frame too large ... looked like an HTTP/1.1 header" error — the h2c client
// never sees the body because the probe is skipped.
func TestAutoH2C_BodyRequestSkipsProbe(t *testing.T) {
	t.Parallel()

	var h2cCalled bool
	h2cRT := rtFunc(func(*http.Request) (*http.Response, error) {
		h2cCalled = true
		return nil, io.ErrUnexpectedEOF
	})
	var gotBody string
	fallback := rtFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	tr := newAutoH2C(h2cRT, fallback)

	r := httptest.NewRequest(http.MethodPost, "http://10.0.0.1:8080", strings.NewReader("payload"))
	resp, err := tr.RoundTrip(r)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, h2cCalled, "a bodied request must not be probed over h2c")
	assert.Equal(t, "payload", gotBody, "fallback receives the untouched body")
	assert.Equal(t, 0, tr.cachedLen(), "skipped probe caches nothing")
}

// A chunked request (ContentLength -1) is treated as having a body and skips the probe.
func TestAutoH2C_ChunkedRequestSkipsProbe(t *testing.T) {
	t.Parallel()

	var h2cCalled bool
	h2cRT := rtFunc(func(*http.Request) (*http.Response, error) {
		h2cCalled = true
		return nil, io.ErrUnexpectedEOF
	})
	fallback := rtFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	tr := newAutoH2C(h2cRT, fallback)

	r := httptest.NewRequest(http.MethodPost, "http://10.0.0.1:8080", strings.NewReader("x"))
	r.ContentLength = -1 // unknown length (chunked)
	_, err := tr.RoundTrip(r)
	require.NoError(t, err)
	assert.False(t, h2cCalled, "unknown-length body must not be probed")
	assert.Equal(t, 0, tr.cachedLen())
}

// Once an upstream is cached h2c-positive (by a bodyless probe), a later bodied
// request DOES ride h2c via the fast path — the body restriction only gates probing.
func TestAutoH2C_BodyRequestUsesCachedH2C(t *testing.T) {
	t.Parallel()

	var h2cBodied bool
	h2cRT := rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			h2cBodied = true
		}
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	fallback := rtFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	tr := newAutoH2C(h2cRT, fallback)

	// bodyless GET probes and caches h2c=true
	_, err := tr.RoundTrip(httptest.NewRequest(http.MethodGet, "http://10.0.0.1:8080", nil))
	require.NoError(t, err)
	e, ok := tr.rawEntry("10.0.0.1:8080")
	require.True(t, ok)
	require.True(t, e.h2c)

	// a subsequent POST takes the cached fast path over h2c
	_, err = tr.RoundTrip(httptest.NewRequest(http.MethodPost, "http://10.0.0.1:8080", strings.NewReader("payload")))
	require.NoError(t, err)
	assert.True(t, h2cBodied, "bodied request rides cached h2c")
}

// A bodyless request whose probe fails before any body work falls back cleanly and
// caches the verdict (the common GET case).
func TestAutoH2C_NoBodyFallsBack(t *testing.T) {
	t.Parallel()

	h2cRT := rtFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
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

// A cached verdict is re-probed once its TTL expires, picking up a Service that
// has since gained h2c support.
func TestAutoH2C_TTLExpiryReprobe(t *testing.T) {
	t.Parallel()

	const key = "10.0.0.1:8080"
	clock := int64(0)
	now := func() time.Time { return time.Unix(0, atomic.LoadInt64(&clock)) }

	var supportsH2C atomic.Bool // upstream starts HTTP/1.1-only
	var h2cCalls int32
	h2cRT := rtFunc(func(*http.Request) (*http.Response, error) {
		atomic.AddInt32(&h2cCalls, 1)
		if supportsH2C.Load() {
			return &http.Response{StatusCode: http.StatusOK}, nil
		}
		return nil, io.ErrUnexpectedEOF
	})
	fallback := rtFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	tr := newAutoH2CTransport(h2cRT, fallback, time.Minute)
	tr.now = now

	doGet := func() {
		r := httptest.NewRequest(http.MethodGet, "http://"+key, nil)
		_, err := tr.RoundTrip(r)
		require.NoError(t, err)
	}

	// 1) cold: probe fails, negative cached
	doGet()
	assert.Equal(t, int32(1), atomic.LoadInt32(&h2cCalls))
	e, ok := tr.rawEntry(key)
	require.True(t, ok)
	assert.False(t, e.h2c)

	// 2) within TTL: cached fast path, no re-probe
	doGet()
	assert.Equal(t, int32(1), atomic.LoadInt32(&h2cCalls), "should not re-probe within TTL")

	// 3) past TTL, upstream now supports h2c: re-probe, positive cached
	supportsH2C.Store(true)
	atomic.StoreInt64(&clock, int64(2*time.Minute))
	doGet()
	assert.Equal(t, int32(2), atomic.LoadInt32(&h2cCalls), "should re-probe after TTL")
	e, ok = tr.rawEntry(key)
	require.True(t, ok)
	assert.True(t, e.h2c, "verdict flipped to h2c after re-probe")
}

// Concurrent requests to a cold HTTP/1.1-only upstream collapse to a single h2c
// probe; the rest fall back to HTTP/1.1 instead of stampeding failed connections.
func TestAutoH2C_SingleflightProbe(t *testing.T) {
	t.Parallel()

	var (
		h2cCalls int32
		fbCalls  int32
	)
	release := make(chan struct{})
	probing := make(chan struct{}, 1)
	h2cRT := rtFunc(func(*http.Request) (*http.Response, error) {
		atomic.AddInt32(&h2cCalls, 1)
		probing <- struct{}{} // signal: prober is in flight, holding the slot
		<-release             // block until the followers have run
		return nil, io.ErrUnexpectedEOF
	})
	fallback := rtFunc(func(*http.Request) (*http.Response, error) {
		atomic.AddInt32(&fbCalls, 1)
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	tr := newAutoH2C(h2cRT, fallback)

	doGet := func() {
		r := httptest.NewRequest(http.MethodGet, "http://10.0.0.1:8080", nil)
		_, err := tr.RoundTrip(r)
		require.NoError(t, err)
	}

	proberDone := make(chan struct{})
	go func() { defer close(proberDone); doGet() }()
	<-probing // prober now holds the single-flight slot

	const followers = 12
	var fw sync.WaitGroup
	for i := 0; i < followers; i++ {
		fw.Add(1)
		go func() { defer fw.Done(); doGet() }()
	}
	fw.Wait() // every follower took the HTTP/1.1 fallback

	assert.Equal(t, int32(1), atomic.LoadInt32(&h2cCalls), "only one request probes h2c")
	assert.Equal(t, int32(followers), atomic.LoadInt32(&fbCalls), "followers fell back")

	close(release)
	<-proberDone

	// prober failed its probe and replayed over HTTP/1.1
	assert.Equal(t, int32(followers+1), atomic.LoadInt32(&fbCalls))
	assert.Equal(t, 1, tr.cachedLen())
}
