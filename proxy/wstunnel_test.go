package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/moonrhythm/parapet/pkg/compress"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"github.com/moonrhythm/parapet-ingress-controller/wsh2"
)

// TestMain re-execs the test binary with GODEBUG=http2xconnect=1 when it's
// missing, so the h2 server advertises SETTINGS_ENABLE_CONNECT_PROTOCOL (read in
// package init). This keeps plain `go test ./...` green everywhere with no CI
// changes: the child inherits the gate, runs the real tests, and its exit code
// propagates.
func TestMain(m *testing.M) {
	const token = "http2xconnect=1"
	if !strings.Contains(os.Getenv("GODEBUG"), token) {
		godebug := token
		if cur := os.Getenv("GODEBUG"); cur != "" {
			godebug = cur + "," + token
		}
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		cmd.Env = append(withoutGODEBUG(os.Environ()), "GODEBUG="+godebug)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				os.Exit(ee.ExitCode())
			}
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func withoutGODEBUG(env []string) []string {
	out := env[:0:0]
	for _, e := range env {
		if strings.HasPrefix(e, "GODEBUG=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

// wsTunnelHandler mimics the wsNormalize middleware + the route handler: it
// normalizes an extended-CONNECT WebSocket handshake and points the proxy at the
// fake pod, then proxies. It is wrapped in compress.Gzip below so the flush
// through http.NewResponseController must traverse a parapet ResponseWriter
// wrapper via Unwrap — the integration check that steady frames actually reach
// the client.
func wsTunnelHandler(t *testing.T, p *Proxy, podAddr string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wsh2.IsExtendedConnect(r) && r.Header.Get(":protocol") == "websocket" {
			r = wsh2.Normalize(r)
		}
		r.URL.Scheme = "http"
		r.URL.Host = podAddr
		p.ServeHTTP(w, r)
	})
}

// startH2CServer serves handler as prior-knowledge h2c on a fresh listener and
// returns its address. GODEBUG=http2xconnect=1 (set by TestMain) makes it
// advertise extended CONNECT.
func startH2CServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	h2s := &http2.Server{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h2s.ServeConn(c, &http2.ServeConnOpts{Handler: handler})
		}
	}()
	return ln.Addr().String()
}

// h2cClient returns an x/net http2.Transport that speaks prior-knowledge h2c.
func h2cClient(t *testing.T) *http2.Transport {
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return tr
}

func extendedConnect(t *testing.T, serverAddr, path string, body io.Reader) *http.Request {
	t.Helper()
	r := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "http", Host: serverAddr, Path: path},
		Host:   "example.com",
		Header: http.Header{},
		Body:   io.NopCloser(body),
	}
	r.Header[":protocol"] = []string{"websocket"}
	r.Header.Set("Sec-WebSocket-Version", "13")
	return r
}

// TestWSTunnelEndToEnd drives a real h2 extended CONNECT through the proxy tunnel
// to a fake pod that speaks the h1 upgrade, and asserts bidirectional bytes flow.
func TestWSTunnelEndToEnd(t *testing.T) {
	keyCh := make(chan string, 1)
	reqCh := make(chan *http.Request, 1)
	podAddr := startFakePod(t, func(conn net.Conn, req *http.Request, br *bufio.Reader) {
		reqCh <- req
		key := req.Header.Get("Sec-WebSocket-Key")
		keyCh <- key
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: chat\r\n\r\n", wsh2.AcceptKey(key))
		// echo client frames back
		_, _ = io.Copy(conn, br)
	})

	p := New()
	h := compress.Gzip().ServeHandler(wsTunnelHandler(t, p, podAddr))
	serverAddr := startH2CServer(t, h)

	pr, pw := io.Pipe()
	tr := h2cClient(t)
	resp, err := tr.RoundTrip(extendedConnect(t, serverAddr, "/chat", pr))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "chat", resp.Header.Get("Sec-WebSocket-Protocol"))
	assert.Empty(t, resp.Header.Get("Sec-WebSocket-Accept"), "accept proof stripped on the h2 side")

	// the pod saw a valid h1 handshake
	podReq := <-reqCh
	assert.Equal(t, http.MethodGet, podReq.Method)
	assert.Equal(t, "websocket", podReq.Header.Get("Upgrade"))
	assert.NotEmpty(t, <-keyCh, "core generated a Sec-WebSocket-Key")

	// client -> pod -> client round trip
	_, err = pw.Write([]byte("ping"))
	require.NoError(t, err)
	got := make([]byte, 4)
	_, err = io.ReadFull(resp.Body, got)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(got))

	pw.Close()
}

// TestWSTunnelRefused verifies a non-101 pod response is forwarded verbatim,
// with its body intact and without the pod-hop's Connection/Transfer-Encoding
// headers leaking through: resp.Body has already been transfer-decoded by the
// time copyHeader runs, so a copied Transfer-Encoding would lie about the
// framing, and Connection is hop-by-hop.
func TestWSTunnelRefused(t *testing.T) {
	podAddr := startFakePod(t, func(conn net.Conn, _ *http.Request, _ *bufio.Reader) {
		fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nnope\n\r\n0\r\n\r\n")
	})

	p := New()
	h := compress.Gzip().ServeHandler(wsTunnelHandler(t, p, podAddr))
	serverAddr := startH2CServer(t, h)

	tr := h2cClient(t)
	resp, err := tr.RoundTrip(extendedConnect(t, serverAddr, "/chat", strings.NewReader("")))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Transfer-Encoding"), "Transfer-Encoding must not leak to the client")
	assert.Empty(t, resp.Header.Get("Connection"), "Connection must not leak to the client")
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "nope\n", string(body))
}

// TestServeWSTunnelDialErrorRetryable pins the dial-error seam: a tunnel dial
// failure panics with a retryable error, which retryMiddleware recovers exactly
// like today's ReverseProxy dial-error panic.
func TestServeWSTunnelDialErrorRetryable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	ln.Close() // now refused

	p := New()
	r := httptest.NewRequest(http.MethodGet, "/ws", nil)
	r.URL.Scheme = "http"
	r.URL.Host = addr
	r.Header.Set("Upgrade", "websocket")
	r = r.WithContext(wsh2.MarkTunnel(r.Context(), http.NoBody))
	w := httptest.NewRecorder()

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		p.ServeHTTP(w, r)
	}()

	err, _ = recovered.(error)
	require.Error(t, err, "dial error panics")
	assert.True(t, IsRetryable(err), "tunnel dial error is retryable")
}

// startFakePod accepts one h1 WebSocket upgrade and hands the connection to fn.
func startFakePod(t *testing.T, fn func(conn net.Conn, req *http.Request, br *bufio.Reader)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
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
	return ln.Addr().String()
}
