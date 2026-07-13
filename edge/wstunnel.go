package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
	"github.com/moonrhythm/parapet-ingress-controller/wsh2"
)

// wsHandshakeTimeout bounds the extended-CONNECT handshake — the h2/h2c dial,
// the request write, and the core's response-header read. x/net's http2.Transport
// has no ResponseHeaderTimeout, so this is enforced by a timer that cancels the
// request context and is disarmed the instant RoundTrip returns; the context then
// lives for the whole (long-lived) WebSocket session. It matches the RPC
// transports' one-minute ResponseHeaderTimeout.
const wsHandshakeTimeout = time.Minute

// errExtendedConnectNotSupported is the message x/net's http2 client returns
// pre-flight (before writing any request bytes) when the peer's first SETTINGS
// did not advertise ENABLE_CONNECT_PROTOCOL. The error type is unexported, so it
// is matched by substring; a missed match degrades to the generic pre-commit
// failure path, which also falls back to HTTP/1.1.
const errExtendedConnectNotSupported = "extended connect not supported by peer"

// wsTunnel translates a client's HTTP/1.1 WebSocket upgrade into an RFC 8441
// extended CONNECT over a dedicated multiplexed transport to the core, so tens of
// thousands of sockets ride a few TCP connections instead of one each. It is nil
// on a Forwarder unless EDGE_UPSTREAM_WS_H2 is set AND the upstream hop is h2.
type wsTunnel struct {
	tr     http.RoundTripper // dedicated: ALPN h2-only (TLS) or prior-knowledge h2c
	scheme string            // "https" (re-encrypt) or "http" (plaintext h2c)
	addr   string            // core host:port
}

var wsFallbackWarn sync.Once

// newWSTunnel builds the dedicated tunnel transport from the same inputs
// NewForwarder gets. It is NEVER the RPC transport: sharing would pin the regular
// traffic's stream budget with long-lived tunnel streams, and the re-encrypt RPC
// transport may ALPN-negotiate HTTP/1.1 (onto which an extended CONNECT would
// serialize as garbage). The TLS transport therefore offers ALPN h2 ONLY — an
// h1-only core fails the handshake cleanly, routing to the h1 fallback.
func newWSTunnel(addr, scheme string, useTLS bool, sni string, getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) *wsTunnel {
	var tr *http2.Transport
	if useTLS {
		// Same SNI / data-plane mTLS client cert as the RPC transport, but ALPN h2
		// only and InsecureSkipVerify (cluster-internal hop, matching the RPC posture).
		cfg := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // cluster-internal hop, matches the RPC transport
			NextProtos:         []string{"h2"},
		}
		if sni != "" {
			cfg.ServerName = sni
		}
		if getClientCert != nil {
			cfg.GetClientCertificate = getClientCert
		}
		tr = &http2.Transport{
			TLSClientConfig:    cfg,
			ReadIdleTimeout:    30 * time.Second,
			PingTimeout:        15 * time.Second,
			DisableCompression: true,
		}
	} else {
		// Prior-knowledge h2c, matching upstream.H2CTransport's own transport shape.
		tr = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
			},
			ReadIdleTimeout:    30 * time.Second,
			PingTimeout:        15 * time.Second,
			DisableCompression: true,
		}
	}
	return &wsTunnel{tr: tr, scheme: scheme, addr: addr}
}

// serve attempts the WS-over-h2 tunnel for a client WebSocket upgrade. It returns
// true when it owns the outcome (tunnel established, core refusal relayed, a
// committed session torn down, or a malformed handshake rejected) and false when
// the caller must fall back to the HTTP/1.1 ReverseProxy path with the ORIGINAL,
// untouched request. The distinction is strict: false is only ever returned
// BEFORE any byte is written to the client, so a fallback never double-serves.
func (t *wsTunnel) serve(w http.ResponseWriter, r *http.Request) (handled bool) {
	// Minimal server-side handshake validation. httputil.ReverseProxy would forward
	// a keyless / non-GET upgrade upstream; reject it here so a malformed handshake
	// never opens a tunnel (and we always have the client key to synthesize 101).
	clientKey := r.Header.Get("Sec-WebSocket-Key")
	if r.Method != http.MethodGet || clientKey == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return true
	}

	// The client conn must be hijackable to splice raw frames. Upgrade requests only
	// arrive on the edge's h1 public listener, so this holds; the check is
	// non-committing (it does not hijack) so a miss falls back cleanly.
	if !canHijack(w) {
		return false
	}

	// One context for the whole session; a timer bounds only the handshake and is
	// disarmed once RoundTrip returns (fact: x/net has no ResponseHeaderTimeout).
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	pr, pw := io.Pipe()
	creq := t.translate(ctx, r, pr)

	timer := time.AfterFunc(wsHandshakeTimeout, cancel)
	resp, err := t.tr.RoundTrip(creq)
	timer.Stop()
	if err != nil {
		// Pre-flight / pre-commit failure — nothing was written to the client, so
		// fall back to HTTP/1.1. The not-supported error is the "core lost its
		// GODEBUG" alarm; a clean ALPN/dial/TLS rejection from an old core lands here
		// too and must NOT 502 the client.
		pw.Close()
		if strings.Contains(err.Error(), errExtendedConnectNotSupported) {
			wsFallbackWarn.Do(func() {
				slog.Warn("edge: core does not advertise WS-over-h2 (extended CONNECT); falling back to HTTP/1.1 — verify GODEBUG=http2xconnect=1 on the core", "error", err)
			})
		} else {
			slog.Warn("edge: ws tunnel handshake failed; falling back to HTTP/1.1", "addr", t.addr, "error", err)
		}
		observe.WSUpstream("http1", "fallback")
		return false
	}

	if resp.StatusCode != http.StatusOK {
		// The core refused the handshake (WAF block / auth / app 4xx). Nothing is
		// hijacked yet, so relay it as a normal h1 response on the client conn.
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		resp.Body.Close()
		pw.Close()
		observe.WSUpstream("h2", "ok")
		return true
	}

	// Accepted. Commit to the client: hijack, write the synthesized 101, then splice.
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		// canHijack said yes, so this is not expected. The core stream is already
		// committed and we cannot fall back — 502 via the still-usable ResponseWriter.
		resp.Body.Close()
		pw.Close()
		slog.Warn("edge: ws tunnel hijack failed after core accepted", "addr", t.addr, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		observe.WSUpstream("h2", "error")
		return true
	}
	defer conn.Close()

	if err := writeClientHandshake(conn, clientKey, resp.Header); err != nil {
		resp.Body.Close()
		pw.Close()
		observe.WSUpstream("h2", "error")
		return true
	}
	observe.WSUpstream("h2", "ok")

	// Splice both directions. The client→core side reads from brw.Reader (not conn)
	// so any bytes the client pipelined before our 101 — already buffered by the
	// hijack — are drained upstream first. Closing an endpoint on one side unblocks
	// the other, so both copies return and serve completes when the session ends.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = wsh2.Copy(pw, brw.Reader, nil)
		pw.Close()
		cancel()
	}()

	_, _ = io.Copy(conn, resp.Body)
	resp.Body.Close()
	conn.Close()
	<-done
	return true
}

// serveH2Inbound tunnels an h2-inbound WebSocket (a client's own RFC 8441
// extended CONNECT, already normalized to GET+Upgrade with the live stream parked
// in the context) to the core over extended CONNECT. Unlike serve there is no
// client key, no 101, and no hijack: the parked stream is the request body
// directly (x/net streams it as the client→core DATA frames) and the client is
// answered with a 200 on its own h2 stream, which is natively full-duplex.
//
// It returns true when it owns the outcome (session spliced, refusal relayed) and
// false ONLY before any byte reaches the client (not-supported / pre-commit
// failure), so the caller falls back to the h1-upgrade bridge — never to
// ReverseProxy, which cannot serve WebSocket on an h2 stream. On a false return it
// counts nothing; the bridge records the terminal outcome (one event per request).
func (t *wsTunnel) serveH2Inbound(w http.ResponseWriter, r *http.Request, stream io.ReadCloser) (handled bool) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// The parked stream IS the request body — no pipe (x/net reads it directly).
	creq := t.translate(ctx, r, stream)

	timer := time.AfterFunc(wsHandshakeTimeout, cancel)
	resp, err := t.tr.RoundTrip(creq)
	timer.Stop()
	if err != nil {
		// ONLY the not-supported error may fall back to the bridge: it is provably
		// pre-flight (x/net checks the peer's SETTINGS before writing anything, so no
		// body goroutine ever started and the parked stream is pristine). Any other
		// failure may have already streamed client frames from the parked stream as
		// DATA frames — a bridge replay would lose them, and a stale x/net body
		// reader could race the bridge for later frames — so it is a 502, never a
		// fallback. (The h1-inbound serve can fall back more broadly because its
		// request body is a pipe that holds nothing until the 101 commits.)
		if strings.Contains(err.Error(), errExtendedConnectNotSupported) {
			wsFallbackWarn.Do(func() {
				slog.Warn("edge: core does not advertise WS-over-h2 (extended CONNECT); falling back to HTTP/1.1 — verify GODEBUG=http2xconnect=1 on the core", "error", err)
			})
			return false
		}
		slog.Warn("edge: ws h2-inbound tunnel handshake failed", "addr", t.addr, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		stream.Close()
		observe.WSUpstream("h2", "error")
		return true
	}

	if resp.StatusCode != http.StatusOK {
		// The core refused the handshake (WAF block / auth / app 4xx). Relay it as a
		// normal response on the client's h2 stream (works fine — no hijack needed).
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		resp.Body.Close()
		stream.Close()
		observe.WSUpstream("h2", "ok")
		return true
	}

	// Accepted. Answer 200 on the client's h2 stream and splice.
	copyWSResponseHeader(w.Header(), resp.Header)
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	flush := func() { _ = rc.Flush() }
	flush() // commit the 200 before any frames
	observe.WSUpstream("h2", "ok")

	// Splice core→client here; the client→core direction is x/net streaming the
	// request body (the parked stream). Closing both endpoints on return unblocks
	// that reader so the request completes when the session ends.
	_ = wsh2.Copy(w, resp.Body, flush)
	stream.Close()
	resp.Body.Close()
	cancel()
	return true
}

// translate builds the extended-CONNECT clone of r on ctx, leaving r untouched so
// the caller can still fall back with the original. body is the client→core pipe.
// Per RFC 8441 the h2 handshake carries no Sec-WebSocket-Key/Accept, and
// Connection/Upgrade/Transfer-Encoding are illegal on h2 (x/net's client rejects
// them); Sec-WebSocket-Version/Protocol/Extensions ride through. Scheme + host
// mirror the Forwarder's Director; Host (→ :authority) and path route on the core.
func (t *wsTunnel) translate(ctx context.Context, r *http.Request, body io.ReadCloser) *http.Request {
	c := r.Clone(ctx)
	c.Method = http.MethodConnect
	c.Body = body
	c.ContentLength = -1
	c.Header.Del("Connection")
	c.Header.Del("Upgrade")
	c.Header.Del("Transfer-Encoding")
	c.Header.Del("Sec-WebSocket-Key")
	// A client-sent Content-Length/Expect describes the h1 upgrade GET, not the
	// tunnel's live, lengthless stream (mirrors wsh2.Normalize's rationale).
	c.Header.Del("Content-Length")
	c.Header.Del("Expect")
	c.Header.Set(":protocol", "websocket")
	c.URL.Scheme = t.scheme
	c.URL.Host = t.addr
	return c
}

// writeClientHandshake writes the synthesized client-facing 101 Switching
// Protocols to the hijacked conn: Sec-WebSocket-Accept is computed from the
// client's original key (the h2 side carried none), and the negotiated
// subprotocol/extensions are echoed from the core's 200.
func writeClientHandshake(conn net.Conn, clientKey string, coreHeader http.Header) error {
	var b bytes.Buffer
	b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Accept: %s\r\n", wsh2.AcceptKey(clientKey))
	for _, h := range []string{"Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
		for _, v := range coreHeader.Values(h) {
			fmt.Fprintf(&b, "%s: %s\r\n", h, v)
		}
	}
	b.WriteString("\r\n")

	_ = conn.SetWriteDeadline(time.Now().Add(wsHandshakeTimeout))
	if _, err := conn.Write(b.Bytes()); err != nil {
		slog.Warn("edge: ws tunnel write 101 failed", "error", err)
		return err
	}
	_ = conn.SetWriteDeadline(time.Time{})
	return nil
}

// isWebSocketUpgrade reports whether r is a WebSocket upgrade handshake. Other
// Upgrade values (e.g. h2c prior-knowledge, unknown protocols) always take the
// existing HTTP/1.1 path.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// canHijack reports whether w's underlying ResponseWriter supports hijacking,
// walking the Unwrap chain exactly as http.ResponseController does — WITHOUT
// hijacking. This lets serve decide to fall back before committing.
func canHijack(w http.ResponseWriter) bool {
	for {
		if _, ok := w.(http.Hijacker); ok {
			return true
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return false
		}
		w = u.Unwrap()
	}
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
// describe the now-closed core hop, not the client's.
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

// copyWSResponseHeader copies the accepted-handshake response headers onto the
// client's h2 stream, minus the hop-by-hop headers and the Sec-WebSocket-Accept
// proof (meaningless on the h2 side — the client's own extended CONNECT carried
// no key, and the core/bridge's accept refers to a different hop).
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
