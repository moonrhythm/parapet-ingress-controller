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
	"github.com/moonrhythm/parapet/pkg/logger"

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
		// var retry *errRetryable
		// if errors.As(err, &retry) {
		// 	panic(err)
		// }
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	},
}

// type errRetryable struct {
// 	err error
// }
//
// func (err *errRetryable) Error() string {
// 	return err.err.Error()
// }
//
// func (err *errRetryable) Unwrap() error {
// 	return err.err
// }

var dialer = &net.Dialer{
	Timeout:   2 * time.Second,
	KeepAlive: time.Minute,
}

type (
	ctxKeyResolver struct{}
	resolver       func() string
)

func dialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	// conn, err = dialer.DialContext(ctx, network, addr)
	// if err == context.Canceled {
	// 	return
	// }
	// if err != nil {
	// 	err = &errRetryable{err}
	// 	return
	// }
	// conn = metric.BackendConnections(ctx, conn, addr)
	// return

	resolve, _ := ctx.Value(ctxKeyResolver{}).(resolver)
	var dialAddr string

	for i := 0; i < 30; i++ {
		dialAddr = addr
		if resolve != nil {
			resolveAddr := resolve()
			if resolveAddr != "" {
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
		return nil, err
	}
	logger.Set(ctx, "serviceTarget", dialAddr)
	conn = metric.BackendConnections(ctx, conn, dialAddr)
	return
}

func backoffDuration(round int) time.Duration {
	if round <= 6 {
		return time.Duration(1<<uint(round)) * 10 * time.Millisecond
	}
	return time.Second
}
