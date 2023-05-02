package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"

	"github.com/golang/glog"
)

var (
	errBadGateway         = errors.New("bad gateway")
	errServiceUnavailable = errors.New("service unavailable")
)

type Proxy struct {
	OnDialError func(addr string)

	reverseProxy  httputil.ReverseProxy
	httpTransport *http.Transport
	h2cTransport  *h2cTransport
}

func New() *Proxy {
	d := newDialer()

	var p Proxy
	d.onError = p.onDialError
	p.httpTransport = newHTTPTransport(d.DialContext)
	p.h2cTransport = newH2CTransport(d.DialContext, p.httpTransport)
	p.reverseProxy = httputil.ReverseProxy{
		Director:   func(_ *http.Request) {},
		BufferPool: newBufferPool(),
		Transport: &gateway{
			Default: p.httpTransport,
			H2C:     p.h2cTransport,
		},
		ModifyResponse: func(resp *http.Response) error {
			switch resp.StatusCode {
			case http.StatusBadGateway:
				return errBadGateway
			case http.StatusServiceUnavailable:
				return errServiceUnavailable
			default:
				return nil
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				// client canceled request
				w.WriteHeader(499)
				return
			}

			glog.Warningf("proxy: upstream error; host=%s, err=%v", r.Host, err)

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

func IsRetryable(err error) bool {
	if isDialError(err) {
		return true
	}
	if errors.Is(err, errBadGateway) {
		return true
	}
	if errors.Is(err, errServiceUnavailable) {
		return true
	}
	return false
}
