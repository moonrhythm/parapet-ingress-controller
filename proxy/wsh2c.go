package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/moonrhythm/parapet-ingress-controller/metric"
	"github.com/moonrhythm/parapet-ingress-controller/wafclaim"
	"github.com/moonrhythm/parapet-ingress-controller/wsh2"
)

// wsH2CNegTTL bounds a cached "pod does not advertise extended CONNECT" verdict.
// It matches the auto-h2c default so a Service that gains support is re-attempted
// on the same cadence; no separate env knob.
const wsH2CNegTTL = 10 * time.Minute

// errExtendedConnectNotSupported is the message x/net's http2 client returns
// pre-flight (before writing any request bytes, before touching req.Body) when the
// peer's first SETTINGS did not advertise ENABLE_CONNECT_PROTOCOL. The error type
// is unexported, so it is matched by substring; a missed match degrades to the
// generic error path (which does not fall back), so the match is the safety hinge
// that keeps the parked stream replayable.
const errExtendedConnectNotSupported = "extended connect not supported by peer"

// EnableWSUpstreamH2C turns on core→pod WebSocket-over-h2c (RFC 8441 extended
// CONNECT). It builds a dedicated prior-knowledge h2c transport — never the RPC
// h2c transport, whose stream budget long-lived tunnels must not pin. Call before
// serving traffic.
func (p *Proxy) EnableWSUpstreamH2C() {
	p.wsUpstreamH2C = true
	p.wsH2C = &http2.Transport{
		AllowHTTP:          true,
		DisableCompression: true,
		ReadIdleTimeout:    30 * time.Second,
		PingTimeout:        15 * time.Second,
		// Dial through p.dialer so bad-addr marking still fires; capture the dial
		// error in the per-request holder (x/net wraps the RoundTrip error, so the
		// holder is the reliable seam for classifying it as retryable).
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			conn, err := p.dialer.DialContext(ctx, network, addr)
			if err != nil {
				if h, ok := ctx.Value(wsDialErrKey{}).(*wsDialErr); ok {
					h.err = err
				}
				return nil, err
			}
			return conn, nil
		},
	}
}

// wsDialErr holds the dial error captured at the DialTLSContext seam for one
// extended-CONNECT attempt.
type wsDialErr struct{ err error }

type wsDialErrKey struct{}

// wsH2CEligible reports whether an extended-CONNECT attempt to the pod should be
// made for r. It never mutates the auto-h2c verdict.
func (p *Proxy) wsH2CEligible(r *http.Request, key string) bool {
	switch r.URL.Scheme {
	case "h2c":
		// explicit appProtocol: h2c — the pod speaks h2c, attempt extended CONNECT.
	case "http":
		// plain http: only when auto-h2c already holds a fresh positive verdict for
		// this Service (established by regular traffic — a WS request must not probe).
		if p.autoH2C == nil || !p.autoH2C.freshPositive(key) {
			return false
		}
	default: // https and anything else stay on the h1-over-TLS path
		return false
	}
	// A fresh negative (peer did not advertise) skips straight to the h1 path.
	return !p.wsH2CNegativeFresh(key)
}

// wsH2CNegativeFresh reports whether key has an unexpired negative verdict.
// Expired entries are deleted on read: with auto-h2c off the fallback key is the
// dialed pod host:port, so pod churn would otherwise grow the map without bound.
func (p *Proxy) wsH2CNegativeFresh(key string) bool {
	v, ok := p.wsH2CNeg.Load(key)
	if !ok {
		return false
	}
	if !time.Now().Before(v.(time.Time)) {
		p.wsH2CNeg.Delete(key)
		return false
	}
	return true
}

// storeWSH2CNegative records a fresh negative verdict for key.
func (p *Proxy) storeWSH2CNegative(key string) {
	p.wsH2CNeg.Store(key, time.Now().Add(wsH2CNegTTL))
}

// tryWSTunnelH2C attempts an RFC 8441 extended CONNECT to the pod over h2c. It
// returns true when it owns the outcome (tunnel spliced, refusal relayed, or a
// non-retryable error 502'd), or panics with a retryable dial error for
// retryMiddleware. It returns false ONLY on a not-supported peer — the pre-flight
// failure leaves the parked stream untouched (fact: RFC 8441 not-supported fails
// before any bytes or any req.Body read), so serveWSTunnel falls through to the h1
// path with a pristine stream.
func (p *Proxy) tryWSTunnelH2C(w http.ResponseWriter, r *http.Request, stream io.ReadCloser, key string) (handled bool) {
	addr := r.URL.Host

	// One context for the whole session; a timer bounds only the handshake and is
	// disarmed once RoundTrip returns (x/net has no ResponseHeaderTimeout). The
	// holder rides this context so DialTLSContext can hand back the dial error.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	holder := &wsDialErr{}
	ctx = context.WithValue(ctx, wsDialErrKey{}, holder)

	creq := buildWSConnect(ctx, r, stream, addr)

	timer := time.AfterFunc(wsHandshakeTimeout, cancel)
	resp, err := p.wsH2C.RoundTrip(creq)
	timer.Stop()
	if err != nil {
		if strings.Contains(err.Error(), errExtendedConnectNotSupported) {
			// Peer does not advertise extended CONNECT: cache the negative and let the
			// caller fall back to the h1 upgrade dial. Nothing was written to the client
			// or read from stream.
			p.storeWSH2CNegative(key)
			metric.WSUpstreamH2C("not_supported")
			return false
		}
		// A dial failure cannot have consumed the request body: preserve phase-1 retry
		// semantics (panic → retryMiddleware). The holder captures it at the dial seam;
		// isDialError is the fallback when a shared/reused dial obscured the holder.
		if holder.err != nil {
			panic(holder.err)
		}
		if isDialError(err) {
			panic(err)
		}
		// Conn died mid-handshake or the stream was reset: the body may have been
		// partially consumed, so a replay could duplicate frames — no fallback, no
		// retry.
		slog.Warn("proxy: ws h2c tunnel handshake failed", "addr", addr, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		metric.WSUpstreamH2C("error")
		metric.WSTunnel("upstream_error")
		return true
	}

	if resp.StatusCode/100 != 2 {
		// The pod refused the handshake (app auth / 404 / ...). The extended CONNECT
		// mechanism itself worked, so count it ok here and relay the refusal like the
		// h1 non-101 path; the refusal detail lives in ws_tunnels{result=refused}.
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		resp.Body.Close()
		stream.Close()
		metric.WSUpstreamH2C("ok")
		metric.WSTunnel("refused")
		return true
	}

	// Accepted. Respond 200 on the (h2 or h1) downstream stream, copying the
	// negotiated subprotocol/extensions minus the pod-hop hop-by-hop headers.
	copyWSResponseHeader(w.Header(), resp.Header)
	w.WriteHeader(http.StatusOK)

	rc := http.NewResponseController(w)
	flush := func() { _ = rc.Flush() }
	flush() // commit the 200 before any frames

	metric.WSUpstreamH2C("ok")
	metric.WSTunnel("tunneled")
	metric.WSTunnelActiveInc()
	defer metric.WSTunnelActiveDec()

	// Single-direction copy pod→client (resp.Body → w). The client→pod direction is
	// x/net streaming creq.Body (= stream) upward as DATA frames, so it needs no copy
	// here; closing both endpoints when this returns ends the session.
	_ = wsh2.Copy(w, resp.Body, flush)
	resp.Body.Close()
	stream.Close()
	return true
}

// buildWSConnect clones the normalized h1-upgrade request into the RFC 8441
// extended-CONNECT shape for the pod, leaving r (and its parked stream) untouched
// so serveWSTunnel can still fall back on a not-supported peer. Connection/Upgrade
// are illegal on h2 (x/net rejects them) and the WAF claim is never the pod's
// business; Sec-WebSocket-Version/Protocol/Extensions ride through. The h2 side
// carries no Sec-WebSocket-Key (RFC 8441 has no key/accept proof). body is the
// parked client→pod stream.
func buildWSConnect(ctx context.Context, r *http.Request, body io.ReadCloser, addr string) *http.Request {
	c := r.Clone(ctx)
	c.Method = http.MethodConnect
	c.Body = body
	c.ContentLength = -1
	c.Header.Del("Connection")
	c.Header.Del("Upgrade")
	c.Header.Del("Transfer-Encoding")
	c.Header.Del(wafclaim.Header)
	c.Header.Set(":protocol", "websocket")
	c.URL.Scheme = "http"
	c.URL.Host = addr
	return c
}
