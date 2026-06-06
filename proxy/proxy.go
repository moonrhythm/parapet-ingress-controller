package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
)

type Proxy struct {
	OnDialError func(addr string)

	reverseProxy  httputil.ReverseProxy
	httpTransport *http.Transport
	h2cTransport  *h2cTransport
	gw            *gateway
	autoH2C       *autoH2CTransport
}

func New() *Proxy {
	d := newDialer()

	var p Proxy
	d.onError = p.onDialError
	p.httpTransport = newHTTPTransport(d.DialContext)
	p.h2cTransport = newH2CTransport(d.DialContext, p.httpTransport)
	p.gw = &gateway{
		Default: p.httpTransport,
		H2C:     p.h2cTransport,
	}
	p.reverseProxy = httputil.ReverseProxy{
		Director:   func(_ *http.Request) {},
		BufferPool: newBufferPool(),
		Transport:  p.gw,
		// No ModifyResponse: an upstream that responded — including with 502/503 —
		// has processed the request, so its response passes through to the client
		// unchanged (status, headers, body). Only connection failures (no response)
		// reach ErrorHandler and may be retried.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				// client canceled request
				w.WriteHeader(499)
				return
			}

			slog.Warn("proxy: upstream error", "host", r.Host, "error", err)

			if IsRetryable(err) {
				// lets handler retry
				panic(err)
			}

			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
	return &p
}

func (p *Proxy) onDialError(addr string) {
	if p.OnDialError != nil {
		p.OnDialError(addr)
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.reverseProxy.ServeHTTP(w, r)
}

func (p *Proxy) ConfigTransport(f func(tr *http.Transport)) {
	f(p.httpTransport)
}

// EnableAutoH2C turns on speculative h2c detection for plain-http upstreams.
// Upstreams that don't speak HTTP/2 are probed once, remembered, and served over
// HTTP/1.1 thereafter (see autoH2CTransport). Call before serving traffic.
func (p *Proxy) EnableAutoH2C() {
	p.autoH2C = &autoH2CTransport{
		h2c:      p.h2cTransport,
		fallback: p.httpTransport,
	}
	p.gw.AutoH2C = p.autoH2C
}

// ResetH2C forgets every remembered h2c-unsupported upstream so they are
// re-probed. It's a no-op when auto-h2c is disabled. Called on route reload so a
// Service that gains h2c support is re-detected without a restart.
func (p *Proxy) ResetH2C() {
	if p.autoH2C != nil {
		p.autoH2C.reset()
	}
}

// AutoH2CEnabled reports whether auto-h2c detection is on. Callers use it to skip
// building the per-Service cache key when the feature is disabled.
func (p *Proxy) AutoH2CEnabled() bool {
	return p.autoH2C != nil
}

// IsRetryable reports whether err is a connection failure that's safe to retry.
// Only dial/connection errors qualify — an upstream that *responded* (even with
// 502/503) has already received and processed the request, so retrying could
// duplicate side effects and amplify load on a failing backend. Those responses
// pass through to the client unchanged instead of being retried.
func IsRetryable(err error) bool {
	return isDialError(err)
}
