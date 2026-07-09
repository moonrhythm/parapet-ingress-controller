package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moonrhythm/parapet/pkg/compress"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/moonrhythm/parapet-ingress-controller/wsh2"
)

// wsH2CTunnelHandler mimics wsNormalize + the route handler, pointing the proxy at
// podAddr with the given upstream scheme (h2c = explicit appProtocol, http = auto).
func wsH2CTunnelHandler(p *Proxy, podAddr, scheme string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wsh2.IsExtendedConnect(r) && r.Header.Get(":protocol") == "websocket" {
			r = wsh2.Normalize(r)
		}
		r.URL.Scheme = scheme
		r.URL.Host = podAddr
		p.ServeHTTP(w, r)
	})
}

// podReq captures the fields of the pod-side request the assertions care about,
// copied out of the handler so the test goroutine never races the body read.
type podReq struct {
	method   string
	protocol string
	key      string
	version  string
}

// startWSH2CEchoPod serves an h2c extended-CONNECT WebSocket that echoes DATA
// frames. GODEBUG=http2xconnect=1 (set by TestMain) makes it advertise the
// setting, so the core's client attempt succeeds.
func startWSH2CEchoPod(t *testing.T, seen chan<- podReq) string {
	return startH2CServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- podReq{
			method:   r.Method,
			protocol: r.Header.Get(":protocol"),
			key:      r.Header.Get("Sec-WebSocket-Key"),
			version:  r.Header.Get("Sec-WebSocket-Version"),
		}
		w.Header().Set("Sec-WebSocket-Protocol", "chat")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				_ = rc.Flush()
			}
			if err != nil {
				return
			}
		}
	}))
}

// startFakePodN is startFakePod that accepts up to n sequential h1 connections, so
// a test can drive several fallback handshakes at the same pod address (the
// negative cache keys on that address).
func startFakePodN(t *testing.T, n int, fn func(conn net.Conn, req *http.Request, br *bufio.Reader)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for i := 0; i < n; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				_ = conn.SetReadDeadline(time.Time{})
				fn(conn, req, br)
			}()
		}
	}()
	return ln.Addr().String()
}

// ws101 answers an h1 WebSocket upgrade with a valid 101 computed from the core's
// generated key, then closes (the empty client stream ends the session at once).
func ws101(conn net.Conn, req *http.Request, _ *bufio.Reader) {
	key := req.Header.Get("Sec-WebSocket-Key")
	fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsh2.AcceptKey(key))
}

// TestWSTunnelH2C_ExtendedConnect drives an extended CONNECT through the core to a
// pod that itself speaks WS-over-h2c: the pod-side hop must be extended CONNECT
// (CONNECT + :protocol, no Sec-WebSocket-Key), and bytes must flow both ways.
func TestWSTunnelH2C_ExtendedConnect(t *testing.T) {
	seen := make(chan podReq, 1)
	podAddr := startWSH2CEchoPod(t, seen)

	p := New()
	p.EnableWSUpstreamH2C()
	h := compress.Gzip().ServeHandler(wsH2CTunnelHandler(p, podAddr, "h2c"))
	serverAddr := startH2CServer(t, h)

	pr, pw := io.Pipe()
	tr := h2cClient(t)
	resp, err := tr.RoundTrip(extendedConnect(t, serverAddr, "/chat", pr))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "chat", resp.Header.Get("Sec-WebSocket-Protocol"))

	// the pod-side hop really was extended CONNECT
	got := <-seen
	assert.Equal(t, http.MethodConnect, got.method)
	assert.Equal(t, "websocket", got.protocol)
	assert.Empty(t, got.key, "RFC 8441 has no Sec-WebSocket-Key on the h2 hop")
	assert.Equal(t, "13", got.version)

	// client -> pod -> client round trip
	_, err = pw.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(resp.Body, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))
	pw.Close()
}

// TestWSTunnelH2C_AutoH2CPositive takes the h2c tunnel for a plain-http upstream
// only when auto-h2c already holds a fresh positive verdict; with no verdict it
// falls through to the h1 upgrade path.
func TestWSTunnelH2C_AutoH2CPositive(t *testing.T) {
	t.Run("fresh positive tunnels over h2c", func(t *testing.T) {
		seen := make(chan podReq, 1)
		podAddr := startWSH2CEchoPod(t, seen)

		p := New()
		p.EnableWSUpstreamH2C()
		p.EnableAutoH2C(time.Minute)
		p.autoH2C.store(podAddr, true) // verdict established by regular traffic

		h := compress.Gzip().ServeHandler(wsH2CTunnelHandler(p, podAddr, "http"))
		serverAddr := startH2CServer(t, h)

		tr := h2cClient(t)
		resp, err := tr.RoundTrip(extendedConnect(t, serverAddr, "/chat", strings.NewReader("")))
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		got := <-seen
		assert.Equal(t, http.MethodConnect, got.method, "pod hop was extended CONNECT")
	})

	t.Run("no verdict falls through to h1", func(t *testing.T) {
		methodCh := make(chan string, 1)
		upgradeCh := make(chan string, 1)
		podAddr := startFakePodN(t, 1, func(conn net.Conn, req *http.Request, br *bufio.Reader) {
			methodCh <- req.Method
			upgradeCh <- req.Header.Get("Upgrade")
			ws101(conn, req, br)
		})

		p := New()
		p.EnableWSUpstreamH2C()
		p.EnableAutoH2C(time.Minute) // enabled, but no verdict for podAddr

		h := compress.Gzip().ServeHandler(wsH2CTunnelHandler(p, podAddr, "http"))
		serverAddr := startH2CServer(t, h)

		tr := h2cClient(t)
		resp, err := tr.RoundTrip(extendedConnect(t, serverAddr, "/chat", strings.NewReader("")))
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, http.MethodGet, <-methodCh, "pod saw the h1 upgrade")
		assert.Equal(t, "websocket", <-upgradeCh)
	})
}

// countingNotSupportedRT returns the extended-connect-not-supported error without
// touching the request body (the real x/net client fails pre-flight), and counts
// how many times it is asked to.
type countingNotSupportedRT struct{ n int32 }

func (s *countingNotSupportedRT) RoundTrip(*http.Request) (*http.Response, error) {
	atomic.AddInt32(&s.n, 1)
	return nil, errors.New("net/http: extended connect not supported by peer")
}

// TestWSTunnelH2C_NotSupportedFallsBack verifies a not-supported peer falls back to
// the h1 path, caches the negative, and skips the attempt on the next request.
func TestWSTunnelH2C_NotSupportedFallsBack(t *testing.T) {
	methodCh := make(chan string, 2)
	podAddr := startFakePodN(t, 2, func(conn net.Conn, req *http.Request, br *bufio.Reader) {
		methodCh <- req.Method
		ws101(conn, req, br)
	})

	p := New()
	p.EnableWSUpstreamH2C()
	stub := &countingNotSupportedRT{}
	p.wsH2C = stub

	serve := func() {
		r := httptest.NewRequest(http.MethodGet, "/ws", nil)
		r.URL.Scheme = "h2c"
		r.URL.Host = podAddr
		r.Header.Set("Upgrade", "websocket")
		r = r.WithContext(wsh2.MarkTunnel(r.Context(), io.NopCloser(strings.NewReader(""))))
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		require.Equal(t, http.StatusOK, w.Code, "not-supported falls back to the h1 tunnel")
	}

	serve()
	assert.True(t, p.wsH2CNegativeFresh(podAddr), "negative verdict cached")
	assert.Equal(t, http.MethodGet, <-methodCh, "first request served over h1")

	serve()
	assert.Equal(t, http.MethodGet, <-methodCh, "second request served over h1")
	assert.Equal(t, int32(1), atomic.LoadInt32(&stub.n), "second request skips the h2c attempt")
}

// TestWSTunnelH2C_Refused relays a pod's non-2xx over h2c as a normal response.
func TestWSTunnelH2C_Refused(t *testing.T) {
	podAddr := startH2CServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-App", "v1")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("nope"))
	}))

	p := New()
	p.EnableWSUpstreamH2C()
	h := compress.Gzip().ServeHandler(wsH2CTunnelHandler(p, podAddr, "h2c"))
	serverAddr := startH2CServer(t, h)

	tr := h2cClient(t)
	resp, err := tr.RoundTrip(extendedConnect(t, serverAddr, "/chat", strings.NewReader("")))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "v1", resp.Header.Get("X-App"), "app headers pass through")
	assert.Empty(t, resp.Header.Get("Connection"), "hop headers stripped")
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "nope", string(body))
}

// TestWSTunnelH2C_DialErrorRetryable pins the h2c dial-error seam: a dead pod addr
// panics with a retryable error, exactly like the h1 tunnel dial-error path.
func TestWSTunnelH2C_DialErrorRetryable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	ln.Close() // now refused

	p := New()
	p.EnableWSUpstreamH2C()
	r := httptest.NewRequest(http.MethodGet, "/ws", nil)
	r.URL.Scheme = "h2c"
	r.URL.Host = addr
	r.Header.Set("Upgrade", "websocket")
	r = r.WithContext(wsh2.MarkTunnel(r.Context(), io.NopCloser(strings.NewReader(""))))
	w := httptest.NewRecorder()

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		p.ServeHTTP(w, r)
	}()

	err, _ = recovered.(error)
	require.Error(t, err, "dial error panics")
	assert.True(t, IsRetryable(err), "h2c tunnel dial error is retryable")
	assert.False(t, p.wsH2CNegativeFresh(addr), "a dial error is not a not-supported verdict")
}
