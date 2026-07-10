package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"github.com/moonrhythm/parapet-ingress-controller/wsh2"
)

// edgeHandler wraps the Forwarder in the shared normalize middleware exactly as
// cmd/edge-proxy mounts it, so an inbound extended CONNECT is normalized before it
// reaches the Forwarder — the h2-inbound entry point under test.
func edgeHandler(f *Forwarder) http.Handler {
	return wsh2.NormalizeHandler(f.ServeHandler(nil), nil)
}

// h2cClient returns an x/net http2.Transport that speaks prior-knowledge h2c —
// the stand-in for a browser talking WS-over-h2 to the edge's :443 listener.
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

// extendedConnect builds a client RFC 8441 extended CONNECT WebSocket handshake.
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

// startFakeH1Core accepts one h1 WebSocket upgrade (the core's h1-upgrade hop the
// edge bridge dials), asserts a Sec-WebSocket-Key is present, answers 101 with the
// correct Accept, and echoes client frames. The observed key is sent on keyCh.
func startFakeH1Core(t *testing.T, keyCh chan<- string) string {
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
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		key := req.Header.Get("Sec-WebSocket-Key")
		select {
		case keyCh <- key:
		default:
		}
		if key == "" {
			fmt.Fprint(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
			return
		}
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsh2.AcceptKey(key))
		_, _ = io.Copy(conn, br) // echo
	}()
	return ln.Addr().String()
}

// TestWSH2Inbound_EndToEnd_Tunnel drives a client WS-over-h2 extended CONNECT into
// the edge (normalize → Forwarder h2 tunnel) → an in-process h2c core (extended
// CONNECT) → a fake pod echo. The client is answered 200 on its own h2 stream (no
// 101/hijack), the echo flows both ways, and the edge→core hop used extended
// CONNECT.
func TestWSH2Inbound_EndToEnd_Tunnel(t *testing.T) {
	podAddr := startFakePod(t)
	saw := make(chan string, 1)
	coreAddr := startH2CCore(t, coreWSHandler(t, podAddr, saw))

	f := NewForwarder(coreAddr, false, true, "", ForwarderTuning{}, nil, nil, true)
	require.NotNil(t, f.ws, "WS tunnel must be enabled")
	edgeAddr := startH2CCore(t, edgeHandler(f))

	pr, pw := io.Pipe()
	tr := h2cClient(t)
	resp, err := tr.RoundTrip(extendedConnect(t, edgeAddr, "/chat", pr))
	require.NoError(t, err)
	// Close the request body (pw) before resp.Body: the h2c client's
	// resp.Body.Close blocks until the still-open request body finishes, so the
	// deferred order (resp.Body first) would deadlock — a client half-close the
	// production path never does (a real client resets the whole connection).
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "client answered 200 on its h2 stream")
	assert.Empty(t, resp.Header.Get("Sec-WebSocket-Accept"), "no accept proof on the h2 side")

	// the edge→core hop really used RFC 8441 extended CONNECT
	assert.Equal(t, "CONNECT :protocol=websocket", <-saw)

	// client -> edge -> core -> pod -> back
	_, err = pw.Write([]byte("hello ws"))
	require.NoError(t, err)
	got := make([]byte, len("hello ws"))
	_, err = io.ReadFull(resp.Body, got)
	require.NoError(t, err)
	assert.Equal(t, "hello ws", string(got))
	pw.Close()
}

// TestWSH2Inbound_EndToEnd_Bridge drives a client WS-over-h2 into an edge whose h2
// tunnel is DISABLED, so the h2-inbound request is served by the h1-upgrade bridge
// to a fake h1 core. The bridge generates a Sec-WebSocket-Key, and the client is
// answered 200 on its h2 stream with bidirectional echo.
func TestWSH2Inbound_EndToEnd_Bridge(t *testing.T) {
	keyCh := make(chan string, 1)
	coreAddr := startFakeH1Core(t, keyCh)

	f := NewForwarder(coreAddr, false, true, "", ForwarderTuning{}, nil, nil, false)
	require.Nil(t, f.ws, "tunnel disabled — bridge is the only h2-inbound path")
	require.NotNil(t, f.bridge)
	edgeAddr := startH2CCore(t, edgeHandler(f))

	pr, pw := io.Pipe()
	tr := h2cClient(t)
	resp, err := tr.RoundTrip(extendedConnect(t, edgeAddr, "/chat", pr))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, <-keyCh, "bridge generated a Sec-WebSocket-Key for the h1 upgrade")

	_, err = pw.Write([]byte("bridge"))
	require.NoError(t, err)
	got := make([]byte, len("bridge"))
	_, err = io.ReadFull(resp.Body, got)
	require.NoError(t, err)
	assert.Equal(t, "bridge", string(got))
	pw.Close()
}

// TestWSH2Inbound_NotSupported_BridgeFallback stubs the tunnel RoundTripper to
// return the not-supported error (an old / GODEBUG-less core). The h2-inbound
// request must fall back to the h1-upgrade bridge, which serves the session — the
// {http1,fallback} accounting path.
func TestWSH2Inbound_NotSupported_BridgeFallback(t *testing.T) {
	keyCh := make(chan string, 1)
	coreAddr := startFakeH1Core(t, keyCh)

	f := NewForwarder(coreAddr, false, true, "", ForwarderTuning{}, nil, nil, true)
	require.NotNil(t, f.ws)
	// The real not-supported error is pre-flight and never reads the body, so the
	// stub must not touch it either (the bridge reuses the same parked stream).
	f.ws.tr = notSupportedRT{}
	edgeAddr := startH2CCore(t, edgeHandler(f))

	pr, pw := io.Pipe()
	tr := h2cClient(t)
	resp, err := tr.RoundTrip(extendedConnect(t, edgeAddr, "/chat", pr))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, <-keyCh, "bridge fallback performed the h1 upgrade to the core")

	_, err = pw.Write([]byte("fb"))
	require.NoError(t, err)
	got := make([]byte, len("fb"))
	_, err = io.ReadFull(resp.Body, got)
	require.NoError(t, err)
	assert.Equal(t, "fb", string(got))
	pw.Close()
}

// notSupportedRT mimics x/net's pre-flight not-supported failure: it returns the
// error WITHOUT reading the request body (the parked client stream), so the
// bridge fallback reuses that stream intact.
type notSupportedRT struct{}

func (notSupportedRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("net/http: extended connect not supported by peer")
}

// TestWSH2Inbound_GenericTunnelError_No502Bridge pins the fallback policy: any
// tunnel failure OTHER than not-supported may have consumed client frames from
// the parked stream (x/net streams the body as soon as headers are written), so
// it must 502 — a bridge replay would silently lose those frames.
func TestWSH2Inbound_GenericTunnelError_NoBridge(t *testing.T) {
	keyCh := make(chan string, 1)
	coreAddr := startFakeH1Core(t, keyCh)

	f := NewForwarder(coreAddr, false, true, "", ForwarderTuning{}, nil, nil, true)
	require.NotNil(t, f.ws)
	f.ws.tr = genericErrRT{}
	edgeAddr := startH2CCore(t, edgeHandler(f))

	pr, pw := io.Pipe()
	tr := h2cClient(t)
	resp, err := tr.RoundTrip(extendedConnect(t, edgeAddr, "/chat", pr))
	require.NoError(t, err)
	// pw must close BEFORE resp.Body.Close(): the h2 client's Close blocks until
	// the request body finishes (same teardown ordering as the tests above).
	defer resp.Body.Close()
	defer pw.Close()

	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	select {
	case k := <-keyCh:
		t.Fatalf("bridge must not run after a generic tunnel error (saw upgrade with key %q)", k)
	default:
	}
}

// genericErrRT mimics a mid-handshake tunnel failure (conn reset after headers
// were written) — the class of error that may have partially consumed the body.
type genericErrRT struct{}

func (genericErrRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("http2: client connection lost")
}

// TestWSH2Inbound_BadProtocol_501 verifies a non-websocket :protocol on an
// inbound extended CONNECT is refused with 501 by the normalize middleware.
func TestWSH2Inbound_BadProtocol_501(t *testing.T) {
	f := NewForwarder("127.0.0.1:1", false, true, "", ForwarderTuning{}, nil, nil, true)
	edgeAddr := startH2CCore(t, edgeHandler(f))

	tr := h2cClient(t)
	r := extendedConnect(t, edgeAddr, "/chat", strings.NewReader(""))
	r.Header[":protocol"] = []string{"bogus"}
	resp, err := tr.RoundTrip(r)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
}

// TestWSH2Inbound_Refused verifies a core refusal (403 on the extended-CONNECT
// handshake) is relayed to the h2-inbound client as a 403 on its stream, with the
// core-hop's Connection/Transfer-Encoding headers stripped.
func TestWSH2Inbound_Refused(t *testing.T) {
	coreAddr := startH2CCore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(http.StatusForbidden)
		_ = http.NewResponseController(w).Flush()
		_, _ = io.WriteString(w, "blocked")
	}))

	f := NewForwarder(coreAddr, false, true, "", ForwarderTuning{}, nil, nil, true)
	edgeAddr := startH2CCore(t, edgeHandler(f))

	tr := h2cClient(t)
	resp, err := tr.RoundTrip(extendedConnect(t, edgeAddr, "/chat", strings.NewReader("")))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Transfer-Encoding"), "Transfer-Encoding must not leak to the client")
	assert.Empty(t, resp.Header.Get("Connection"), "Connection must not leak to the client")
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "blocked", string(body))
}
