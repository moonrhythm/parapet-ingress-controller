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
	"github.com/moonrhythm/parapet/pkg/upstream"

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

// TODO: make Transport configurable
var httpTransport = &http.Transport{
	DialContext:           dialContext,
	MaxIdleConnsPerHost:   1000,
	IdleConnTimeout:       10 * time.Minute,
	ExpectContinueTimeout: time.Second,
	DisableCompression:    true,
	ResponseHeaderTimeout: 5 * time.Minute,
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
}

var h2cTransport = &upstream.H2CTransport{}

type transportGateway struct{}

func (transportGateway) RoundTrip(r *http.Request) (*http.Response, error) {
	var tr http.RoundTripper
	switch r.URL.Scheme {
	default:
		tr = httpTransport
	case "h2c":
		tr = h2cTransport
	}

	return tr.RoundTrip(r)
}

var proxy = &httputil.ReverseProxy{
	Director: func(req *http.Request) {
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	},
	BufferPool: &bufferPool{sync.Pool{New: func() interface{} { return make([]byte, bufferSize) }}},
	Transport:  transportGateway{},
	ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		if err == context.Canceled {
			// client canceled request
			w.WriteHeader(499)
			return
		}

		glog.Warningf("upstream error (err=%v)", err)

		var netOpError *net.OpError
		if errors.As(err, &netOpError) && netOpError.Op == "dial" {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}

		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	},
}

var dialer = &net.Dialer{
	Timeout:   2 * time.Second,
	KeepAlive: time.Minute,
}

type (
	ctxKeyResolver struct{}
	resolver       func() string
)

func dialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	resolve, _ := ctx.Value(ctxKeyResolver{}).(resolver)
	var dialAddr string

	var i int
	for i = 0; i < 30; i++ {
		dialAddr = addr
		if resolve != nil {
			if resolveAddr := resolve(); resolveAddr != "" {
				dialAddr = resolveAddr
			}
		}

		conn, err = dialer.DialContext(ctx, network, dialAddr)
		if err == nil || err == context.Canceled {
			break
		}

		select {
		case <-time.After(backoffDuration(i)):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		glog.Errorf("can not connect (addr=%s, dial=%s, retry=%d, err=%v)", addr, dialAddr, i, err)
		return nil, err
	}

	if i == 0 {
		glog.Infof("connected (addr=%s, dial=%s)", addr, dialAddr)
	} else {
		glog.Warningf("connected (addr=%s, dial=%s, retry=%d)", addr, dialAddr, i)
	}

	conn = metric.BackendConnections(ctx, conn, dialAddr)
	return
}

const maxBackoffDuration = 3 * time.Second

func backoffDuration(round int) (t time.Duration) {
	t = time.Duration(1<<uint(round)) * 10 * time.Millisecond
	if t > maxBackoffDuration {
		t = maxBackoffDuration
	}
	return
}
