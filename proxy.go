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
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialContext,
		MaxConnsPerHost:       200,
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

func dialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	for i := 0; i < 15; i++ {
		conn, err = dialer.DialContext(ctx, network, addr)
		if err == nil || err == context.Canceled {
			break
		}

		select {
		case <-time.After(backoffDuration(i)):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return
}

func backoffDuration(round int) time.Duration {
	if round <= 6 {
		return time.Duration(1<<uint(round)) * 10 * time.Millisecond
	}
	return time.Second
}
