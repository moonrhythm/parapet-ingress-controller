package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/metric"
	"github.com/moonrhythm/parapet-ingress-controller/state"
)

type dialer struct {
	inner   net.Dialer
	onError func(addr string)
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
			if d.onError != nil {
				d.onError(addr)
			}
			slog.Error("proxy: can not connect", "addr", addr, "error", err)
		}
		return
	}

	// Attribute the connection to its destination Service, not the dialed pod
	// address. The transport calls DialContext with the request context, so the
	// route state stamped by makeHandler is available here; a pod addr maps to a
	// single Service, so the attribution is stable across connection reuse.
	s := state.Get(ctx)
	conn = metric.BackendConnections(conn, s["serviceType"], s["namespace"], s["serviceName"])
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
