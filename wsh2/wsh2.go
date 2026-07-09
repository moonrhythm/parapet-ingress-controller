// Package wsh2 bridges RFC 8441 extended-CONNECT WebSocket handshakes (the
// HTTP/2 form) to the HTTP/1.1 upgrade the rest of the chain speaks. It is pure
// (no k8s deps) so both the core proxy and the edge can import it.
//
// An h2 WebSocket handshake arrives as `:method: CONNECT` + `:protocol:
// websocket` with the live client→server byte stream as the request body. The
// core cannot inspect or splice that stream through the existing middleware
// chain (body inspectors would block on / consume WebSocket frames), so
// Normalize rewrites the request into the h1-upgrade shape and detaches the
// stream into the request context — after which everything downstream is
// oblivious to the difference from an h1 handshake.
package wsh2

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"
)

// wsGUID is the RFC 6455 §1.3 magic constant folded into the accept-key hash.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// IsExtendedConnect reports whether r is an RFC 8441 extended CONNECT — the
// HTTP/2 form of a WebSocket handshake. Go's h2 server surfaces the `:protocol`
// pseudo-header in r.Header; an h1 client cannot produce it (colon-prefixed
// field names are invalid HTTP/1.1 tokens and net/http rejects them), so this
// match is inherently h2-only and not client-spoofable over h1.
func IsExtendedConnect(r *http.Request) bool {
	return r.Method == http.MethodConnect && r.Header.Get(":protocol") != ""
}

// Normalize rewrites an extended CONNECT WebSocket handshake in place into the
// h1-upgrade shape the rest of the chain understands, parks the live
// client→server stream in the request context (retrievable via TunnelStream),
// and returns the request carrying that context. The caller must have confirmed
// IsExtendedConnect and a `websocket` protocol.
//
// After Normalize the request is indistinguishable from an h1 WebSocket
// handshake: request.method sees GET, and body inspectors (WAF InspectBody,
// Coraza request body) see an empty body — exactly as they would for an h1
// upgrade, whose body they also never read. Detaching the stream is mandatory:
// left as r.Body it would be consumed by those inspectors, eating WebSocket
// frames before the proxy could splice them.
func Normalize(r *http.Request) *http.Request {
	r.Method = http.MethodGet
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Del(":protocol")
	// The spliced 200 response is byte-transparent; it must never be wrapped by
	// the compress.Gzip/Zstd middlewares, so the handshake must not advertise a
	// content coding.
	r.Header.Del("Accept-Encoding")
	// Go's h2 server keeps a client-sent content-length as a regular header on
	// an extended CONNECT, but after the stream is detached below the handshake
	// truthfully has no body. A surviving Content-Length (or Transfer-Encoding /
	// Expect) would be written to the pod by the core's h1 handshake dial and
	// desync the pod's parser — it would read WebSocket frames as body bytes.
	r.Header.Del("Content-Length")
	r.Header.Del("Transfer-Encoding")
	r.Header.Del("Expect")

	stream := r.Body
	if stream == nil {
		stream = http.NoBody
	}
	ctx := MarkTunnel(r.Context(), stream)
	r.Body = http.NoBody
	r.ContentLength = 0
	return r.WithContext(ctx)
}

type tunnelCtxKey struct{}

// MarkTunnel returns a child context carrying the parked client→server stream of
// a normalized WebSocket handshake. The value is immutable and never cleared, so
// it is safe to read from any goroutine that holds the context (unlike the
// pooled per-request state map).
func MarkTunnel(ctx context.Context, stream io.ReadCloser) context.Context {
	return context.WithValue(ctx, tunnelCtxKey{}, stream)
}

// TunnelStream returns the parked stream set by MarkTunnel, if any.
func TunnelStream(ctx context.Context) (io.ReadCloser, bool) {
	s, ok := ctx.Value(tunnelCtxKey{}).(io.ReadCloser)
	return s, ok
}

// GenerateKey returns a fresh base64-encoded 16-byte Sec-WebSocket-Key (RFC 6455
// §4.1). The h2 handshake carries no key, so the core mints one for the h1
// upgrade dial to the pod.
func GenerateKey() string {
	var b [16]byte
	// crypto/rand.Read never returns an error on the platforms we target.
	_, _ = rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}

// AcceptKey computes the RFC 6455 §4.2.2 Sec-WebSocket-Accept value for key:
// base64(SHA1(key + wsGUID)).
func AcceptKey(key string) string {
	h := sha1.New()
	io.WriteString(h, key)
	io.WriteString(h, wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// CheckAccept reports whether accept is the correct Sec-WebSocket-Accept for
// key, in constant time. A mismatch means the peer did not complete the RFC 6455
// handshake correctly.
func CheckAccept(accept, key string) bool {
	want := AcceptKey(key)
	return subtle.ConstantTimeCompare([]byte(accept), []byte(want)) == 1
}
