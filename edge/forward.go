package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"sync"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/upstream"
)

// Forwarder is the terminal middleware that forwards a request to the in-cluster
// parapet. It uses plaintext h2c by default, or re-encrypts with TLS when
// EDGE_UPSTREAM_TLS=true (presenting EDGE_UPSTREAM_SNI as the SNI/Host for the
// handshake). It does NOT rewrite the HTTP Host — the original client Host is
// forwarded, as in the Rust edge.
//
// The X-Forwarded-For / X-Real-Ip / X-Forwarded-Proto headers are set by the
// parapet server's own inbound proxy layer (the edge is the first hop and trusts
// no upstream, so it overwrites them with the true peer / connection scheme).
// X-Forwarded-Country / X-Forwarded-ASN are set by forwardGeoHeaders.
type Forwarder struct {
	rp *httputil.ReverseProxy
}

// NewForwarder builds a forwarder to addr (host:port). useTLS selects re-encrypt
// (TLS) vs plaintext HTTP/1.1; sni is the SNI/Host presented when re-encrypting
// (ignored otherwise; "" lets the transport default to addr's host).
//
// The plaintext hop is HTTP/1.1, matching the former Rust edge (pingora's
// HttpPeer with tls=false defaults to HTTP/1.1, not h2c); parapet's :80 accepts
// it. Re-encrypt uses TLS with InsecureSkipVerify (a cluster-internal hop,
// matching the controller's upstream posture).
func NewForwarder(addr string, useTLS bool, sni string) *Forwarder {
	var tr http.RoundTripper
	if useTLS {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // cluster-internal hop, matches the controller's upstream posture
		if sni != "" {
			tlsConfig.ServerName = sni
		}
		// HTTPSTransport sets r.URL.Scheme = "https" and dials r.URL.Host with TLS.
		tr = &upstream.HTTPSTransport{TLSClientConfig: tlsConfig}
	} else {
		// HTTPTransport sets r.URL.Scheme = "http" and speaks HTTP/1.1.
		tr = &upstream.HTTPTransport{}
	}

	rp := &httputil.ReverseProxy{
		// The transport sets the scheme; the Director only needs the host. The
		// path/query and Host header are forwarded verbatim (parapet routes on
		// them). RemoteAddr is cleared in ServeHandler so ReverseProxy doesn't
		// re-append X-Forwarded-For — the parapet server already set the true one.
		Director:   func(r *http.Request) { r.URL.Host = addr },
		Transport:  tr,
		BufferPool: bufferPool,
		ErrorLog:   slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return // client went away
			}
			slog.Warn("edge: upstream error", "addr", addr, "error", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
	return &Forwarder{rp: rp}
}

// ServeHandler implements parapet.Middleware. It is terminal — the next handler
// is ignored (the request is forwarded upstream).
func (f *Forwarder) ServeHandler(_ http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "" // stop ReverseProxy re-appending X-Forwarded-For
		f.rp.ServeHTTP(w, r)
	})
}

var _ parapet.Middleware = (*Forwarder)(nil)

// bufferPool is a shared 16 KiB buffer pool for the reverse-proxy copy loop,
// matching the controller's proxy.
var bufferPool httputil.BufferPool = &bytesPool{
	p: sync.Pool{New: func() any { b := make([]byte, 16*1024); return &b }},
}

type bytesPool struct{ p sync.Pool }

func (bp *bytesPool) Get() []byte  { return *bp.p.Get().(*[]byte) }
func (bp *bytesPool) Put(b []byte) { bp.p.Put(&b) }
