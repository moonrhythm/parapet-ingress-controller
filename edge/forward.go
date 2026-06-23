package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/upstream"
)

// Forwarder is the terminal middleware that forwards a request to the in-cluster
// parapet. By default it speaks h2c on the plaintext hop and ALPN-negotiated h2
// (with HTTP/1.1 fallback) on the re-encrypt hop; set EDGE_UPSTREAM_HTTP2=false to
// force HTTP/1.1 on either. It re-encrypts with TLS when EDGE_UPSTREAM_TLS=true
// (presenting EDGE_UPSTREAM_SNI as the SNI/Host for the handshake). It does NOT
// rewrite the HTTP Host — the original client Host is forwarded.
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

// defaultMaxIdleConnsPerHost mirrors parapet's upstream.defaultMaxIdleConns (32):
// the idle keep-alive pool kept per core host when ForwarderTuning leaves it at 0.
const defaultMaxIdleConnsPerHost = 32

// ForwarderTuning bounds the edge→core connection pool per upstream host. The
// zero value preserves the historical behavior: no connection ceiling
// (MaxConnsPerHost == 0 ⇒ unlimited) and parapet's default idle pool (32).
//
// MaxConnsPerHost is a hard ceiling on the total (active + idle) connections to
// each core host, applied to the HTTP/1.1 transports and the re-encrypt
// ForceAttemptHTTP2 transport (net/http enforces it at the dial layer for both
// the h2 and HTTP/1.1-fallback conns it manages). The DEFAULT plaintext h2c path
// multiplexes every request over a small number of connections via
// golang.org/x/net/http2.Transport, which has no per-host connection limit — so
// the ceiling there bounds only the HTTP/1.1 Upgrade/WebSocket fallback, not the
// multiplexed stream traffic (which needs few connections by construction).
type ForwarderTuning struct {
	MaxConnsPerHost     int // 0 = unlimited (no hard ceiling)
	MaxIdleConnsPerHost int // 0 = parapet default (32)
}

func (t ForwarderTuning) idle() int {
	if t.MaxIdleConnsPerHost > 0 {
		return t.MaxIdleConnsPerHost
	}
	return defaultMaxIdleConnsPerHost
}

// NewForwarder builds a forwarder to addr (host:port).
//
// useTLS selects re-encrypt (TLS) vs plaintext; sni is the SNI/Host presented when
// re-encrypting (ignored otherwise; "" lets the transport default to addr's host).
//
// enableHTTP2 (default on; EDGE_UPSTREAM_HTTP2) picks the upstream protocol within
// each mode. The core accepts both upgraded protocols out of the box — parapet's :80
// server runs with H2C=true and its :443 server offers h2 via ALPN:
//   - plaintext  → h2c prior-knowledge via parapet's upstream.H2CTransport;
//     HTTP/1.1 when disabled.
//   - re-encrypt → ALPN-negotiated h2 with HTTP/1.1 fallback via a ForceAttemptHTTP2
//     http.Transport (h2TLSTransport); HTTP/1.1-over-TLS when disabled.
//
// WebSocket/Upgrade requests always ride HTTP/1.1 regardless: httputil.ReverseProxy
// has no HTTP/2 upgrade path (no RFC 8441) and an h2 connection rejects the
// Connection/Upgrade request headers. H2CTransport downgrades them itself; the
// re-encrypt path routes them to a dedicated HTTP/1.1-over-TLS transport.
//
// getClientCert, when non-nil (and useTLS), presents the edge's data-plane mTLS
// client cert on the re-encrypt handshake so the core can CA-only-trust this edge
// (EDGE_DATAPLANE_MTLS); it rides h2 or HTTP/1.1 identically. Re-encrypt uses TLS
// with InsecureSkipVerify (a cluster-internal hop, matching the controller's upstream
// posture) — the edge authenticates ITSELF to the core with its client cert; it does
// not yet verify the core's server cert. onCertReject, when non-nil, fires when the
// CORE rejects the edge's data-plane client cert in the re-encrypt TLS handshake — the
// reactive force-re-mint floor. It is the coordinator's reactive Trigger; nil when
// data-plane mTLS is off.
//
// tuning bounds the per-host connection pool to the core (see ForwarderTuning);
// the zero value keeps the historical unbounded/idle-32 behavior.
func NewForwarder(addr string, useTLS, enableHTTP2 bool, sni string, tuning ForwarderTuning, getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error), onCertReject func()) *Forwarder {
	var tr http.RoundTripper
	switch {
	case useTLS:
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // cluster-internal hop, matches the controller's upstream posture
		if sni != "" {
			tlsConfig.ServerName = sni
		}
		if getClientCert != nil {
			tlsConfig.GetClientCertificate = getClientCert
		}
		// HTTPSTransport sets r.URL.Scheme = "https" and dials r.URL.Host with TLS,
		// HTTP/1.1 only (net/http won't auto-enable h2 with a custom TLS config).
		h1 := &upstream.HTTPSTransport{
			TLSClientConfig: tlsConfig,
			MaxConn:         tuning.MaxConnsPerHost,
			MaxIdleConns:    tuning.idle(),
		}
		if enableHTTP2 {
			tr = newH2TLSTransport(tlsConfig, tuning, h1)
		} else {
			tr = h1
		}
	case enableHTTP2:
		// Plaintext h2c (prior-knowledge) to the core's H2C=true :80 listener.
		// H2CTransport sets r.URL.Scheme = "http" and downgrades Upgrade/WebSocket
		// requests to HTTP/1.1. The multiplexed h2 path has no per-host conn cap;
		// the ceiling applies to the HTTP/1.1 Upgrade fallback we wire up here.
		tr = &upstream.H2CTransport{HTTPTransport: h2cFallbackTransport(tuning)}
	default:
		// HTTPTransport sets r.URL.Scheme = "http" and speaks HTTP/1.1.
		tr = &upstream.HTTPTransport{
			MaxConn:      tuning.MaxConnsPerHost,
			MaxIdleConns: tuning.idle(),
		}
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	rp := &httputil.ReverseProxy{
		// The Director sets the scheme + host. The upstream.* transports also set the
		// scheme, but the plain http.Transport behind h2TLSTransport does not, so the
		// Director must. The path/query and Host header are forwarded verbatim (parapet
		// routes on them). RemoteAddr is cleared in ServeHandler so ReverseProxy doesn't
		// re-append X-Forwarded-For — the parapet server already set the true one.
		Director:   func(r *http.Request) { r.URL.Scheme = scheme; r.URL.Host = addr },
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

// h2TLSTransport forwards over re-encrypted TLS, preferring ALPN-negotiated HTTP/2
// for ordinary requests while keeping WebSocket/Upgrade requests on HTTP/1.1 — an
// HTTP/2 connection rejects the Connection/Upgrade request headers, so they need a
// dedicated HTTP/1.1 transport (this mirrors parapet's upstream.H2CTransport for the
// plaintext hop). Both transports share one tls.Config (same mTLS client cert / SNI),
// so the data-plane-mTLS handshake is identical on either protocol.
type h2TLSTransport struct {
	h2 http.RoundTripper // ForceAttemptHTTP2: negotiates h2, falls back to HTTP/1.1
	h1 http.RoundTripper // HTTP/1.1-over-TLS, for Upgrade requests
}

func newH2TLSTransport(tlsConfig *tls.Config, tuning ForwarderTuning, h1 http.RoundTripper) *h2TLSTransport {
	return &h2TLSTransport{
		// ForceAttemptHTTP2 makes net/http wire up the bundled http2 transport even
		// though we supply a custom TLSClientConfig + DialContext (which otherwise trips
		// net/http's conservative "don't surprise me" opt-out — see Transport.protocols).
		// ALPN then negotiates h2, falling back to HTTP/1.1 if the core only offers it.
		// Fields mirror upstream.HTTPSTransport's defaults so only the protocol changes;
		// DisableCompression keeps the proxy hop byte-transparent (no auto-gzip).
		// MaxConnsPerHost caps total conns to the core (net/http enforces it for the h2
		// and HTTP/1.1-fallback conns it manages); 0 leaves it unbounded.
		h2: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSClientConfig:       tlsConfig,
			ForceAttemptHTTP2:     true,
			MaxConnsPerHost:       tuning.MaxConnsPerHost,
			MaxIdleConnsPerHost:   tuning.idle(),
			IdleConnTimeout:       10 * time.Minute,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: time.Minute,
			DisableCompression:    true,
		},
		h1: h1,
	}
}

// h2cFallbackTransport builds the HTTP/1.1 transport that upstream.H2CTransport
// uses for Upgrade/WebSocket requests (the multiplexed h2c path can't carry
// them). It mirrors parapet's own default h2c fallback but threads the connection
// ceiling through, so EDGE_UPSTREAM_MAX_CONNS_PER_HOST also bounds the plaintext
// Upgrade path. A 0 ceiling leaves it unbounded, matching parapet's default.
func h2cFallbackTransport(tuning ForwarderTuning) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		MaxConnsPerHost:       tuning.MaxConnsPerHost,
		MaxIdleConnsPerHost:   tuning.idle(),
		IdleConnTimeout:       10 * time.Minute,
		ResponseHeaderTimeout: time.Minute,
		DisableCompression:    true,
	}
}

// RoundTrip routes Upgrade requests to HTTP/1.1 and everything else to the
// h2-preferring transport. r.URL.Scheme is already "https" (set by the Director).
func (t *h2TLSTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("Upgrade") != "" {
		return t.h1.RoundTrip(r)
	}
	return t.h2.RoundTrip(r)
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
