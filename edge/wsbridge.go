package edge

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
	"github.com/moonrhythm/parapet-ingress-controller/wsh2"
)

// wsBridge serves an h2-inbound WebSocket (a normalized client extended CONNECT,
// stream parked in the context) by dialing the core over the HTTP/1.1 upgrade it
// always speaks — the reverse of the core's own pod dial (proxy.serveWSTunnel).
// It is the unconditional fallback for h2-inbound WebSocket: it works even when
// the h2 tunnel (wsTunnel) is disabled or the core doesn't advertise extended
// CONNECT, since ReverseProxy cannot serve WebSocket on an h2 response stream.
type wsBridge struct {
	addr          string
	useTLS        bool
	sni           string
	getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

func newWSBridge(addr string, useTLS bool, sni string, getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) *wsBridge {
	return &wsBridge{addr: addr, useTLS: useTLS, sni: sni, getClientCert: getClientCert}
}

// serve dials the core, performs the h1 WebSocket upgrade, and — on 101 — answers
// the client with a 200 on its h2 stream and splices both directions. fallback
// selects the success accounting: true when a tunnel was attempted but the core
// didn't advertise extended CONNECT (the {http1,fallback} "core lost its GODEBUG"
// alarm), false when the tunnel is disabled ({http1,ok}). A dial or handshake
// failure is a 502 with {http1,error} — nothing usable reached the client yet.
func (b *wsBridge) serve(w http.ResponseWriter, r *http.Request, stream io.ReadCloser, fallback bool) {
	ctx := r.Context()

	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", b.addr)
	if err != nil {
		slog.Warn("edge: ws bridge dial failed", "addr", b.addr, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		stream.Close()
		observe.WSUpstream("http1", "error")
		return
	}
	// Closure, not `defer conn.Close()`: conn is reassigned to the TLS wrapper
	// below, and the close must tear down that final conn.
	defer func() { conn.Close() }()

	if b.useTLS {
		// Re-encrypt with the same SNI / data-plane mTLS posture as the RPC transport
		// but HTTP/1.1 ONLY (this hop speaks the h1 WebSocket upgrade, not h2).
		cfg := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // cluster-internal hop, matches the RPC transport
			NextProtos:         []string{"http/1.1"},
		}
		if b.sni != "" {
			cfg.ServerName = b.sni
		}
		if b.getClientCert != nil {
			cfg.GetClientCertificate = b.getClientCert
		}
		tlsConn := tls.Client(conn, cfg)
		_ = conn.SetDeadline(time.Now().Add(wsHandshakeTimeout))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			slog.Warn("edge: ws bridge tls handshake failed", "addr", b.addr, "error", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			stream.Close()
			observe.WSUpstream("http1", "error")
			return
		}
		conn = tlsConn
	}

	key := wsh2.GenerateKey()
	handshake := buildBridgeHandshake(r, key)

	_ = conn.SetWriteDeadline(time.Now().Add(wsHandshakeTimeout))
	if _, err := conn.Write(handshake); err != nil {
		slog.Warn("edge: ws bridge write handshake failed", "addr", b.addr, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		stream.Close()
		observe.WSUpstream("http1", "error")
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(wsHandshakeTimeout))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		slog.Warn("edge: ws bridge read response failed", "addr", b.addr, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		stream.Close()
		observe.WSUpstream("http1", "error")
		return
	}

	result := "ok"
	if fallback {
		result = "fallback"
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// The core refused the handshake (WAF / auth / app 4xx). Relay it as a normal
		// response on the client's h2 stream; the h1 hop itself worked.
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		resp.Body.Close()
		stream.Close()
		observe.WSUpstream("http1", result)
		return
	}

	if !wsh2.CheckAccept(resp.Header.Get("Sec-WebSocket-Accept"), key) {
		slog.Warn("edge: ws bridge bad Sec-WebSocket-Accept", "addr", b.addr)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		stream.Close()
		observe.WSUpstream("http1", "error")
		return
	}

	// Accepted. Clear the handshake deadlines — the session is long-lived.
	_ = conn.SetDeadline(time.Time{})

	copyWSResponseHeader(w.Header(), resp.Header)
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	flush := func() { _ = rc.Flush() }
	flush() // commit the 200 before any frames

	observe.WSUpstream("http1", result)

	// Splice both directions. The core→client side reads from br (not conn) so it
	// drains any bytes the core pipelined after the 101 that ReadResponse buffered.
	// Closing an endpoint when one direction ends unblocks the other.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = wsh2.Copy(conn, stream, nil)
		conn.Close()
	}()

	_ = wsh2.Copy(w, br, flush)
	stream.Close()
	conn.Close()
	<-done
}

// buildBridgeHandshake renders the HTTP/1.1 WebSocket upgrade request to the core.
// r is already normalized (Connection: Upgrade, Upgrade: websocket,
// Sec-WebSocket-Version/Protocol/Extensions, no Content-Length/Accept-Encoding);
// it stamps the generated Sec-WebSocket-Key (the h2 side carried none). Unlike the
// core's pod handshake it keeps any X-Parapet-Waf claim the edge stamped — the
// core is the claim's audience, not the pod.
func buildBridgeHandshake(r *http.Request, key string) []byte {
	r.Header.Set("Sec-WebSocket-Key", key)

	var b bytes.Buffer
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", r.URL.RequestURI())
	fmt.Fprintf(&b, "Host: %s\r\n", r.Host)
	_ = r.Header.Write(&b)
	b.WriteString("\r\n")
	return b.Bytes()
}
