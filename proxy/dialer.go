package proxy

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/golang/glog"

	"github.com/moonrhythm/parapet-ingress-controller/metric"
	"github.com/moonrhythm/parapet-ingress-controller/route"
)

type dialer struct {
	inner net.Dialer
}

func newDialer() *dialer {
	return &dialer{
		inner: net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
}

func (d *dialer) DialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	conn, err = d.inner.DialContext(ctx, network, addr)
	if err != nil {
		if ctx.Err() == nil { // parent context is not canceled
			route.MarkBad(addr)
			glog.Errorf("proxy: can not connect; addr=%s, err=%v", addr, err)
		}
		return
	}

	conn = metric.BackendConnections(conn, addr)
	return
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
