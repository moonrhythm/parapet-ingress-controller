package controller

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/golang/glog"

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

var proxy = &httputil.ReverseProxy{
	Director: func(req *http.Request) {
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	},
	BufferPool: &bufferPool{sync.Pool{New: func() interface{} { return make([]byte, bufferSize) }}},
	Transport: &http.Transport{
		DialContext:           dialContext,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       10 * time.Minute,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		ResponseHeaderTimeout: 5 * time.Minute,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
	ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		if err == context.Canceled {
			// client canceled request
			return
		}

		glog.Warning(err)
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
		glog.Errorf("can not connect to %s (addr=%s, retry=%d, err=%v)", addr, dialAddr, i, err)
		return nil, err
	}

	if i == 0 {
		glog.Infof("connected to %s (addr=%s)", addr, dialAddr)
	} else {
		glog.Warningf("connected to %s (addr=%s, retry=%d)", addr, dialAddr, i)
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
