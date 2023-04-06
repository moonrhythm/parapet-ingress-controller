package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/golang/glog"
	"golang.org/x/net/http2"

	"github.com/moonrhythm/parapet-ingress-controller/metric"
)

const bufferSize = 16 * 1024

type bufferPool struct {
	sync.Pool
}

func (p *bufferPool) Get() []byte {
	return p.Pool.Get().([]byte)
}

func (p *bufferPool) Put(b []byte) {
	p.Pool.Put(b)
}

var Transport = &http.Transport{
	DialContext:           dialContext,
	MaxIdleConnsPerHost:   100,
	IdleConnTimeout:       10 * time.Second,
	ExpectContinueTimeout: time.Second,
	DisableCompression:    true,
	ResponseHeaderTimeout: 3 * time.Minute,
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
}

type _h2cTransport struct {
	*http2.Transport
}

func (t *_h2cTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = "http"

	if r.Header.Get("Upgrade") != "" {
		return Transport.RoundTrip(r)
	}

	return t.Transport.RoundTrip(r)
}

var h2cTransport = &_h2cTransport{
	&http2.Transport{
		AllowHTTP:          true,
		DisableCompression: true,
		DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialContext(context.Background(), network, addr)
		},
	},
}

type transportGateway struct{}

func (transportGateway) RoundTrip(r *http.Request) (*http.Response, error) {
	var tr http.RoundTripper
	switch r.URL.Scheme {
	default:
		tr = Transport
	case "h2c":
		tr = h2cTransport
	}

	return tr.RoundTrip(r)
}

var (
	errBadGateway         = errors.New("bad gateway")
	errServiceUnavailable = errors.New("service unavailable")
)

var proxy = &httputil.ReverseProxy{
	Director:   func(_ *http.Request) {},
	BufferPool: &bufferPool{sync.Pool{New: func() interface{} { return make([]byte, bufferSize) }}},
	Transport:  transportGateway{},
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
		if err == context.Canceled {
			// client canceled request
			w.WriteHeader(499)
			return
		}

		glog.Warningf("upstream error (err=%v)", err)

		if isRetryable(err) {
			// lets handler retry
			panic(err)
		}

		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	},
}

func isDialError(err error) bool {
	if err == nil {
		return false
	}
	// go1.19 i/o timeout error will now satisfy errors.Is(err, context.DeadlineExceeded)
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netOpError *net.OpError
	return errors.As(err, &netOpError) && netOpError.Op == "dial"
}

var dialer = &net.Dialer{
	Timeout:   2 * time.Second,
	KeepAlive: time.Minute,
}

func dialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	conn, err = dialer.DialContext(ctx, network, addr)
	if err != nil {
		select {
		default:
			globalBadAddrTable.MarkBad(addr)
		case <-ctx.Done(): // parent context canceled, do not mark bad
		}

		glog.Errorf("can not connect (addr=%s, err=%v)", addr, err)
		return
	}

	conn = metric.BackendConnections(conn, addr)
	return
}
