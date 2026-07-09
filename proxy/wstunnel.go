package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/metric"
	"github.com/moonrhythm/parapet-ingress-controller/wafclaim"
	"github.com/moonrhythm/parapet-ingress-controller/wsh2"
)

// wsHandshakeTimeout bounds the TLS handshake, the upgrade-request write, and the
// pod's response-header read, matching newHTTPTransport's ResponseHeaderTimeout.
// Deadlines are cleared before splicing — a live WebSocket session is long-lived.
const wsHandshakeTimeout = 3 * time.Minute

// serveWSTunnel bridges a normalized extended-CONNECT WebSocket handshake to the
// pod over the HTTP/1.1 upgrade it already speaks, then splices bytes both ways.
// r.URL.Host is the resolved pod ip:port and r.URL.Scheme is http/https/h2c (set
// by the route handler); stream is the parked client→server byte stream.
func (p *Proxy) serveWSTunnel(w http.ResponseWriter, r *http.Request, stream io.ReadCloser) {
	ctx := r.Context()
	addr := r.URL.Host

	conn, err := p.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		// Dial error before the handshake: nothing was sent and the request body is
		// http.NoBody, so this is retryable exactly like ReverseProxy.ErrorHandler's
		// dial-error panic. The dialer already ran onError (bad-addr marking) and
		// logged; retryMiddleware recovers this to retry / bad-gateway.
		panic(err)
	}
	// Closure, not `defer conn.Close()`: conn is reassigned to the TLS wrapper
	// below, and the close must tear down that final conn (with close-notify), not
	// the captured raw TCP conn.
	defer func() { conn.Close() }()

	// https upstream: re-encrypt over TLS, HTTP/1.1 only (no h2 ALPN — this hop
	// speaks the h1 WebSocket upgrade). Matches newHTTPTransport's TLS posture.
	if r.URL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		_ = conn.SetDeadline(time.Now().Add(wsHandshakeTimeout))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			// The TCP connection was established, so the request may have reached the
			// pod; do not retry. Nothing is written to the client yet.
			slog.Warn("proxy: ws tunnel tls handshake failed", "addr", addr, "error", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			metric.WSTunnel("upstream_error")
			return
		}
		conn = tlsConn
	}

	key := wsh2.GenerateKey()
	handshake := buildWSHandshake(r, key)

	_ = conn.SetWriteDeadline(time.Now().Add(wsHandshakeTimeout))
	if _, err := conn.Write(handshake); err != nil {
		slog.Warn("proxy: ws tunnel write handshake failed", "addr", addr, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		metric.WSTunnel("upstream_error")
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(wsHandshakeTimeout))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		// The request reached the pod; a failed/absent response must not be replayed.
		slog.Warn("proxy: ws tunnel read response failed", "addr", addr, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		metric.WSTunnel("upstream_error")
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// The pod refused the handshake (app auth / 404 / ...). Forward it as a
		// normal response; the edge (or a direct h2 client) translates the non-200
		// back into a non-101 for its own client.
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		resp.Body.Close()
		metric.WSTunnel("refused")
		return
	}

	if !wsh2.CheckAccept(resp.Header.Get("Sec-WebSocket-Accept"), key) {
		slog.Warn("proxy: ws tunnel bad Sec-WebSocket-Accept", "addr", addr)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		metric.WSTunnel("upstream_error")
		return
	}

	// Accepted. Clear the handshake deadlines — the session is long-lived.
	_ = conn.SetDeadline(time.Time{})

	// Respond 200 on the h2 stream (the h2 side has no 101 / Sec-WebSocket-Accept):
	// copy the negotiated subprotocol/extensions, dropping the pod-hop hop-by-hop
	// headers and the accept proof, which is meaningless upstream of the h2 stream.
	copyWSResponseHeader(w.Header(), resp.Header)
	w.WriteHeader(http.StatusOK)

	rc := http.NewResponseController(w)
	flush := func() { _ = rc.Flush() }
	flush() // commit the 200 before any frames

	metric.WSTunnel("tunneled")
	metric.WSTunnelActiveInc()
	defer metric.WSTunnelActiveDec()

	// Splice both directions. The pod→client side reads from br (not conn) so it
	// drains any bytes the pod pipelined after the 101 that ReadResponse buffered.
	// Closing an endpoint when one direction ends unblocks the other, so both
	// copies return and the handler completes when the session ends.
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

// buildWSHandshake renders the HTTP/1.1 WebSocket upgrade request for the pod.
// The request headers are already normalized (Connection: Upgrade, Upgrade:
// websocket, Sec-WebSocket-Version/Protocol/Extensions); it stamps the generated
// Sec-WebSocket-Key (the h2 side carried none) and drops the edge→core WAF claim,
// which is never the pod's business.
func buildWSHandshake(r *http.Request, key string) []byte {
	r.Header.Del(wafclaim.Header)
	r.Header.Set("Sec-WebSocket-Key", key)

	var b bytes.Buffer
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", r.URL.RequestURI())
	fmt.Fprintf(&b, "Host: %s\r\n", r.Host)
	_ = r.Header.Write(&b)
	b.WriteString("\r\n")
	return b.Bytes()
}

// hopHeaders are the connection-scoped header fields httputil.ReverseProxy
// strips when relaying a response — they describe this hop, not the payload,
// and must never survive onto a different connection.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func isHopHeader(k string) bool {
	ck := http.CanonicalHeaderKey(k)
	for _, h := range hopHeaders {
		if ck == h {
			return true
		}
	}
	return false
}

// copyHeader copies header values from src to dst, dropping hop-by-hop
// headers. resp.Body is already transfer-decoded, so a copied
// Transfer-Encoding would lie about the framing on the client connection
// (Go's h1 server trusts a handler-set TE, corrupting the response); the rest
// describe the now-closed pod hop, not the client's.
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		if isHopHeader(k) {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// copyWSResponseHeader copies the pod's 101 response headers onto the h2 stream
// response, minus the pod-hop hop-by-hop headers and the Sec-WebSocket-Accept
// proof (meaningless on the h2 side; the edge synthesizes its own toward the
// client).
func copyWSResponseHeader(dst, src http.Header) {
	for k, vv := range src {
		if isHopHeader(k) || http.CanonicalHeaderKey(k) == "Sec-Websocket-Accept" {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
