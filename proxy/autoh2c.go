package proxy

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/moonrhythm/parapet/pkg/header"

	"github.com/moonrhythm/parapet-ingress-controller/state"
)

const defaultH2CProbeTTL = 10 * time.Minute

// autoH2CTransport speculatively tries h2c (HTTP/2 cleartext) for plain-http
// upstreams and falls back to HTTP/1.1 when the upstream doesn't speak HTTP/2.
// The probe outcome — h2c-capable or HTTP/1.1-only — is cached per-Service
// (keyed via request state) with a TTL, so each upstream is periodically
// re-probed and a Service that gains (or loses) h2c support is re-detected
// without a controller restart.
//
// Concurrent probes for the same upstream are collapsed (single-flight): only
// one request probes an unknown/expired upstream at a time, while the rest use
// HTTP/1.1 instead of piling on a herd of failed h2c connections. A fresh cached
// outcome takes the fast path and never reaches the single-flight guard, so
// steady h2c traffic is fully multiplexed and never serialized.
type autoH2CTransport struct {
	h2c      http.RoundTripper // *h2cTransport — HTTP/2 cleartext
	fallback http.RoundTripper // *http.Transport — HTTP/1.1
	ttl      time.Duration
	now      func() time.Time // injectable clock (real time.Now in production)

	entries sync.Map // upstream key (string) -> h2cEntry
	probing sync.Map // upstream key (string) -> struct{}{} (probe in flight)
}

// h2cEntry is a cached probe outcome, valid until deadline.
type h2cEntry struct {
	h2c      bool // true = upstream speaks h2c; false = HTTP/1.1-only
	deadline time.Time
}

func newAutoH2CTransport(h2c, fallback http.RoundTripper, ttl time.Duration) *autoH2CTransport {
	if ttl <= 0 {
		ttl = defaultH2CProbeTTL
	}
	return &autoH2CTransport{
		h2c:      h2c,
		fallback: fallback,
		ttl:      ttl,
		now:      time.Now,
	}
}

func (t *autoH2CTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	key := upstreamKey(r)

	// WebSocket/Upgrade can only be tunneled over HTTP/1.1 (httputil.ReverseProxy has
	// no RFC 8441 HTTP/2 path), so it ALWAYS takes the fallback and is never probed or
	// cached. Checked before the cache lookup so an upstream cached h2c-positive still
	// routes its upgrades over HTTP/1.1 — this layer owns the invariant rather than
	// leaning on h2cTransport's own guard.
	if header.Exists(r.Header, header.Upgrade) {
		return t.fallback.RoundTrip(r)
	}

	// Fast path: a fresh cached outcome routes directly — no probing, no
	// single-flight, so steady h2c traffic is fully multiplexed. A cached-h2c upstream
	// serves bodied requests (POST/gRPC) over h2c here; the body restriction below only
	// gates probing, not steady-state routing.
	if e, ok := t.lookup(key); ok {
		if e.h2c {
			return t.h2c.RoundTrip(r)
		}
		return t.fallback.RoundTrip(r)
	}

	// Only bodyless requests probe. A failed h2c probe needs to replay over HTTP/1.1,
	// but the h2c client streams any request body as DATA frames (consuming it) before
	// its read loop detects the HTTP/1.1 peer and fails — leaving nothing to replay and
	// surfacing "http2: frame too large ... looked like an HTTP/1.1 header". Restricting
	// probes to bodyless requests (GET/HEAD/...) sidesteps that with no buffering. A
	// body-carrying request to an as-yet-unknown upstream uses HTTP/1.1 without probing
	// or caching; a later bodyless request establishes the verdict for the whole Service.
	// (Trade-off: a plain-http upstream that is h2c-only AND only ever receives bodied
	// requests never auto-upgrades — those should set appProtocol: h2c explicitly.)
	if hasBody(r) {
		return t.fallback.RoundTrip(r)
	}

	// Unknown or expired: single-flight the probe. Only one request per upstream
	// probes at a time; the rest use HTTP/1.1 rather than pile on failed h2c
	// connections (the herd this guards against is the failing-probe burst right
	// after a cold start or TTL expiry).
	if _, busy := t.probing.LoadOrStore(key, struct{}{}); busy {
		return t.fallback.RoundTrip(r)
	}
	defer t.probing.Delete(key)

	resp, err := t.h2c.RoundTrip(r)
	if err == nil {
		t.store(key, true)
		return resp, nil
	}

	// A dial error means the pod is down, not that it lacks h2c support: leave the
	// cache untouched and propagate so ErrorHandler / retryMiddleware can handle it
	// like any other connection failure.
	if isDialError(err) {
		return nil, err
	}

	// Any other error means "no HTTP/2": cache the verdict and replay over HTTP/1.1.
	// The request is bodyless, so the replay is always safe.
	t.store(key, false)
	slog.Info("proxy: upstream does not support h2c, falling back to http/1.1",
		"upstream", key, "error", err)
	r.URL.Scheme = "http"
	return t.fallback.RoundTrip(r)
}

// hasBody reports whether the request carries a request body. It keys off
// ContentLength (0 = no body; >0 or -1/unknown-chunked = has a body) rather than
// r.Body, which is non-nil even for bodyless server requests.
func hasBody(r *http.Request) bool {
	return r.ContentLength != 0
}

// lookup returns the cached entry if present and not yet expired.
func (t *autoH2CTransport) lookup(key string) (h2cEntry, bool) {
	v, ok := t.entries.Load(key)
	if !ok {
		return h2cEntry{}, false
	}
	e := v.(h2cEntry)
	if !t.now().Before(e.deadline) {
		return h2cEntry{}, false // expired — caller re-probes
	}
	return e, true
}

// store records a probe outcome with a fresh TTL.
func (t *autoH2CTransport) store(key string, supportsH2C bool) {
	t.entries.Store(key, h2cEntry{h2c: supportsH2C, deadline: t.now().Add(t.ttl)})
}

// upstreamKey identifies the upstream for the cache. It prefers the stable
// per-Service key stamped into the request state by the controller, and falls
// back to the dialed host:port when absent.
func upstreamKey(r *http.Request) string {
	if k := state.Get(r.Context())["upstreamKey"]; k != "" {
		return k
	}
	return r.URL.Host
}
