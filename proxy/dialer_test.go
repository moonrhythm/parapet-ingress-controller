package proxy

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/moonrhythm/parapet-ingress-controller/state"
)

func TestBackendAttrRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := WithBackendAttr(context.Background(), "ClusterIP", "ns", "svc")
	a := backendAttrFromContext(ctx)
	assert.Equal(t, "ClusterIP", a.serviceType)
	assert.Equal(t, "ns", a.namespace)
	assert.Equal(t, "svc", a.serviceName)

	// Absent value yields a zero attribution, not a panic.
	assert.Equal(t, backendAttr{}, backendAttrFromContext(context.Background()))
}

// TestDialContextDoesNotRaceRecycledState reproduces the dialer crash fixed by
// carrying backend attribution in an immutable context value.
//
// The transport may run DialContext on a background goroutine (it races a fresh
// dial against an idle connection) that outlives the originating request. By the
// time it reaches the attribution read, state.Middleware has cleared the pooled
// per-request State and another request may already be writing to it. The old
// dialer read those labels from that map, so the late read raced the writer —
// "fatal error: concurrent map read and map write". The fix reads an immutable
// value instead, so the dial goroutine never touches the recyclable map.
//
// A single writer goroutine continuously stamps then clears the shared map (so
// writer-vs-writer never races); many concurrent dialers exercise the read path.
// Run with -race: the pre-fix dialer trips the detector here, the fixed one does
// not.
func TestDialContextDoesNotRaceRecycledState(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	addr := ln.Addr().String()

	d := newDialer()

	// The same shape state.Middleware injects: a pooled map reachable from the
	// dial context, and (in the fixed code) the immutable attribution beside it.
	s := state.State{}
	ctx := state.NewContext(context.Background(), s)
	ctx = WithBackendAttr(ctx, "ClusterIP", "ns", "svc")

	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-stop:
				return
			default:
				// putState clears the map; the next request re-stamps it.
				s["serviceType"] = "ClusterIP"
				s["namespace"] = "ns"
				s["serviceName"] = "svc"
				clear(s)
			}
		}
	}()

	const dialers = 8
	const dialsPerGoroutine = 400
	var wg sync.WaitGroup
	for i := 0; i < dialers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < dialsPerGoroutine; j++ {
				conn, err := d.DialContext(ctx, "tcp", addr)
				if err == nil {
					conn.Close()
				}
			}
		}()
	}
	wg.Wait()

	close(stop)
	<-writerDone
}
