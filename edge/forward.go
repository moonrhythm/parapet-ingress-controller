package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/upstream"
)

// Forwarder is the terminal middleware that forwards a request to the in-cluster
// parapet. It uses plaintext h2c by default, or re-encrypts with TLS when
// EDGE_UPSTREAM_TLS=true (presenting EDGE_UPSTREAM_SNI as the SNI/Host for the
// handshake). It does NOT rewrite the HTTP Host — the original client Host is
// forwarded.
//
// The X-Forwarded-For / X-Real-Ip / X-Forwarded-Proto headers are set by the
// parapet server's own inbound proxy layer. By default the edge is the first hop
// and trusts no upstream, so it overwrites them with the true peer / connection
// scheme; when TRUST_PROXY matches the immediate peer (e.g. the edge sits behind
// Cloudflare) parapet instead honors the inbound X-Forwarded-* so the real client
// IP flows through. X-Forwarded-Country / X-Forwarded-ASN are set by
// forwardGeoHeaders.
type Forwarder struct {
	rp *httputil.ReverseProxy
}

// NewForwarder builds a forwarder to addr (host:port). useTLS selects re-encrypt
// (TLS) vs plaintext HTTP/1.1; sni is the SNI/Host presented when re-encrypting
// (ignored otherwise; "" lets the transport default to addr's host). getClientCert,
// when non-nil (and useTLS), presents the edge's data-plane mTLS client cert on the
// re-encrypt handshake so the core can CA-only-trust this edge (EDGE_DATAPLANE_MTLS).
//
// The plaintext hop is HTTP/1.1 (not h2c); parapet's :80 accepts it.
// Re-encrypt uses TLS with InsecureSkipVerify (a cluster-internal hop,
// matching the controller's upstream posture) — the edge authenticates ITSELF to
// the core with its client cert; it does not yet verify the core's server cert.
// onCertReject, when non-nil, fires when the CORE rejects the edge's data-plane client
// cert in the re-encrypt TLS handshake — the reactive force-re-mint floor. It is the
// coordinator's reactive Trigger; nil when data-plane mTLS is off.
func NewForwarder(addr string, useTLS bool, sni string, getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error), onCertReject func()) *Forwarder {
	var tr http.RoundTripper
	if useTLS {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // cluster-internal hop, matches the controller's upstream posture
		if sni != "" {
			tlsConfig.ServerName = sni
		}
		if getClientCert != nil {
			tlsConfig.GetClientCertificate = getClientCert
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
			// Reactive force-re-mint floor: if the CORE rejected our client cert in the
			// handshake, fire the (non-blocking) reactive trigger BEFORE the 502. The
			// request still 502s; once the new leaf lands, subsequent requests succeed.
			if onCertReject != nil && isClientCertRejected(err) {
				onCertReject()
			}
			slog.Warn("edge: upstream error", "addr", addr, "error", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
	return &Forwarder{rp: rp}
}

// isClientCertRejected reports whether err is the CORE rejecting the edge's client cert
// in the re-encrypt TLS handshake — and ONLY that. It is deliberately PARANOID: a false
// positive turns an unrelated core outage into a fleet-wide re-mint storm, so it
// matches only a PEER-sent ("remote error: tls: ...") cert-verify alert and excludes a
// locally-raised alert, dial errors, timeouts, and any HTTP status (a healthy core's
// 5xx is a response that never reaches ErrorHandler).
func isClientCertRejected(err error) bool {
	if err == nil {
		return false
	}
	// A locally-generated alert is the EDGE rejecting the core (we don't verify the core
	// today, but be explicit) — re-minting our own cert can't fix that. Exclude it.
	var ae *tls.AlertError
	if errors.As(err, &ae) {
		return false
	}
	s := strings.ToLower(err.Error())
	if !strings.Contains(s, "remote error: tls:") {
		return false // not a peer-sent TLS alert (dial error / timeout / etc.)
	}
	// NOTE: certificate_expired is deliberately ABSENT — an expired leaf is owned by the
	// remaining-life renewal floor (MaybeRenew), not the reactive path. Including it would
	// let an expiry-driven reactive mint (which produces a fresh leaf with the SAME ca_id)
	// feed the no-flip reactive breaker.
	for _, alert := range []string{
		"bad certificate",      // Go's rendering of bad_certificate
		"certificate required", // certificate_required (core wants a cert / rejected none)
		"unknown certificate authority",
		"unknown ca",          // unknown_ca
		"certificate unknown", // certificate_unknown
		"certificate revoked", // certificate_revoked
	} {
		if strings.Contains(s, alert) {
			return true
		}
	}
	return false
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
