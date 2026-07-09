package edge

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"github.com/moonrhythm/parapet-ingress-controller/wsh2"
)

// TestMain re-execs the edge test binary with GODEBUG=http2xconnect=1 when it's
// missing, so the in-process h2c "core" advertises SETTINGS_ENABLE_CONNECT_PROTOCOL
// (read in package init). Copied from proxy/wstunnel_test.go; keeps plain
// `go test ./...` green everywhere with no CI changes.
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

// startFakePod accepts one h1 WebSocket upgrade and echoes client frames back —
// the pod at the far end of the core hop.
func startFakePod(t *testing.T) string {
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
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: chat\r\n\r\n", wsh2.AcceptKey(key))
		_, _ = io.Copy(conn, br) // echo
	}()
	return ln.Addr().String()
}

// startH2CCore serves handler as prior-knowledge h2c; GODEBUG=http2xconnect=1
// (set by TestMain) makes it advertise extended CONNECT — a stand-in for the core's
// :80 H2C listener.
func startH2CCore(t *testing.T, handler http.Handler) string {
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

// coreWSHandler reproduces the REAL phase-1 core behavior with the shared wsh2
// package: normalize the extended CONNECT (the two-line wsNormalize middleware),
// then tunnel to the pod over the h1 upgrade (proxy.serveWSTunnel's logic). It is
// hand-rolled rather than importing the proxy package on purpose: proxy pulls in
// the metric package, and the edge test binary already wires observe's lazily
// registered waf_matches/coraza_matches — linking metric would duplicate-register
// and panic (the invariant import_boundary_test.go guards). wsh2 IS the phase-1
// shared code, so this exercises the genuine translation/splice.
func coreWSHandler(t *testing.T, podAddr string, saw chan<- string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case saw <- r.Method + " :protocol=" + r.Header.Get(":protocol"):
		default:
		}
		if !wsh2.IsExtendedConnect(r) || r.Header.Get(":protocol") != "websocket" {
			http.Error(w, "not a ws handshake", http.StatusBadRequest)
			return
		}
		r = wsh2.Normalize(r)
		stream, ok := wsh2.TunnelStream(r.Context())
		require.True(t, ok)
		coreTunnelToPod(t, w, r, podAddr, stream)
	})
}

func coreTunnelToPod(t *testing.T, w http.ResponseWriter, r *http.Request, podAddr string, stream io.ReadCloser) {
	conn, err := net.Dial("tcp", podAddr)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer conn.Close()

	key := wsh2.GenerateKey()
	var b bytes.Buffer
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n", r.URL.RequestURI(), r.Host, key)
	for _, h := range []string{"Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
		for _, v := range r.Header.Values(h) {
			fmt.Fprintf(&b, "%s: %s\r\n", h, v)
		}
	}
	b.WriteString("\r\n")
	if _, err := conn.Write(b.Bytes()); err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		resp.Body.Close()
		return
	}
	require.True(t, wsh2.CheckAccept(resp.Header.Get("Sec-WebSocket-Accept"), key))

	for _, h := range []string{"Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
		for _, v := range resp.Header.Values(h) {
			w.Header().Add(h, v)
		}
	}
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = wsh2.Copy(conn, stream, nil)
		conn.Close()
	}()
	_ = wsh2.Copy(w, br, func() { _ = rc.Flush() })
	stream.Close()
	conn.Close()
	<-done
}

// dialWSClient performs a raw HTTP/1.1 WebSocket handshake against the edge and
// returns the connection + buffered reader positioned at the frame stream, plus the
// 101 response. The repo has no WebSocket client dep, so the handshake is hand-rolled.
func dialWSClient(t *testing.T, edgeAddr, path string) (net.Conn, *bufio.Reader, *http.Response, string) {
	t.Helper()
	c, err := net.Dial("tcp", edgeAddr)
	require.NoError(t, err)
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	key := wsh2.GenerateKey()
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n", path, key)

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	return c, br, resp, key
}

func edgeAddrOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return strings.TrimPrefix(srv.URL, "http://")
}

// TestWSTunnel_EndToEnd_H2C drives the full loop: a real h1 WebSocket client → the
// edge Forwarder (WS-h2 on, plaintext h2c) → an in-process h2c core (extended
// CONNECT) → a fake pod echo server. It asserts a well-formed 101 with the correct
// Accept, bidirectional echo, and that the edge→core hop actually used extended
// CONNECT.
func TestWSTunnel_EndToEnd_H2C(t *testing.T) {
	podAddr := startFakePod(t)
	saw := make(chan string, 1)
	coreAddr := startH2CCore(t, coreWSHandler(t, podAddr, saw))

	f := NewForwarder(coreAddr, false, true, "", ForwarderTuning{}, nil, nil, true)
	require.NotNil(t, f.ws, "WS tunnel must be enabled")
	edge := httptest.NewServer(f.ServeHandler(nil))
	defer edge.Close()

	conn, br, resp, key := dialWSClient(t, edgeAddrOf(t, edge), "/chat")
	defer conn.Close()

	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	assert.Equal(t, wsh2.AcceptKey(key), resp.Header.Get("Sec-WebSocket-Accept"), "edge synthesizes Accept from the client key")
	assert.Equal(t, "chat", resp.Header.Get("Sec-WebSocket-Protocol"), "negotiated subprotocol echoed to the client")

	// the core hop really used RFC 8441 extended CONNECT
	assert.Equal(t, "CONNECT :protocol=websocket", <-saw)

	// client -> pod -> client echo
	_, err := conn.Write([]byte("hello ws"))
	require.NoError(t, err)
	got := make([]byte, len("hello ws"))
	_, err = io.ReadFull(br, got)
	require.NoError(t, err)
	assert.Equal(t, "hello ws", string(got))
}

// TestWSTunnel_EndToEnd_Refused verifies a core refusal (403 on the handshake) is
// relayed to the client as a well-formed h1 403, not a hang, with its body intact
// and without the core-hop's Connection/Transfer-Encoding headers leaking
// through: resp.Body has already been transfer-decoded by the time copyHeader
// runs, so a copied Transfer-Encoding would lie about the framing, and
// Connection is hop-by-hop.
func TestWSTunnel_EndToEnd_Refused(t *testing.T) {
	coreAddr := startH2CCore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The core (WAF/auth) refuses the extended-CONNECT handshake outright,
		// echoing hop-by-hop headers the way a naive relay of its own upstream
		// hop might.
		w.Header().Set("Connection", "close")
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(http.StatusForbidden)
		_ = http.NewResponseController(w).Flush() // commit headers without a Content-Length
		_, _ = io.WriteString(w, "blocked")
	}))

	f := NewForwarder(coreAddr, false, true, "", ForwarderTuning{}, nil, nil, true)
	edge := httptest.NewServer(f.ServeHandler(nil))
	defer edge.Close()

	conn, _, resp, _ := dialWSClient(t, edgeAddrOf(t, edge), "/chat")
	defer conn.Close()

	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Transfer-Encoding"), "Transfer-Encoding must not leak to the client")
	assert.Empty(t, resp.Header.Get("Connection"), "Connection must not leak to the client")
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "blocked", string(body))
}

// TestWSTunnel_EndToEnd_Fallback points the edge at an HTTP/1.1-only core: the h2c
// tunnel preface fails, so the request must still succeed via the h1 ReverseProxy
// upgrade path. (An old core / GODEBUG-less core is the same clean-failure class.)
func TestWSTunnel_EndToEnd_Fallback(t *testing.T) {
	// h1-only core that echoes a WebSocket upgrade directly.
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		key := r.Header.Get("Sec-WebSocket-Key")
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsh2.AcceptKey(key))
		_, _ = io.Copy(conn, brw)
	}))
	defer core.Close()
	coreAddr := edgeAddrOf(t, core)

	f := NewForwarder(coreAddr, false, true, "", ForwarderTuning{}, nil, nil, true)
	edge := httptest.NewServer(f.ServeHandler(nil))
	defer edge.Close()

	conn, br, resp, key := dialWSClient(t, edgeAddrOf(t, edge), "/chat")
	defer conn.Close()

	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode, "fell back to h1 upgrade")
	assert.Equal(t, wsh2.AcceptKey(key), resp.Header.Get("Sec-WebSocket-Accept"))

	_, err := conn.Write([]byte("via-h1"))
	require.NoError(t, err)
	got := make([]byte, len("via-h1"))
	_, err = io.ReadFull(br, got)
	require.NoError(t, err)
	assert.Equal(t, "via-h1", string(got))
}
