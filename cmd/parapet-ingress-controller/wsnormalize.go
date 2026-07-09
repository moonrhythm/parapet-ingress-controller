package main

import (
	"net/http"

	"github.com/moonrhythm/parapet"

	"github.com/moonrhythm/parapet-ingress-controller/metric"
	"github.com/moonrhythm/parapet-ingress-controller/wsh2"
)

// wsNormalize rewrites an RFC 8441 extended-CONNECT WebSocket handshake into the
// HTTP/1.1 upgrade shape the rest of the chain understands, so WAF/Coraza/rate
// limits/routing/plugins behave identically for an h1 and an h2 WebSocket
// handshake. It is mounted first, before everything in SPEC.md's per-request
// order, and is unconditional: a non-extended-CONNECT request pays only the two
// header checks in IsExtendedConnect. Whether the h2 server actually accepts
// extended CONNECT is gated by GODEBUG=http2xconnect=1; without it this is dead
// code that never fires.
func wsNormalize() parapet.Middleware {
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !wsh2.IsExtendedConnect(r) {
				h.ServeHTTP(w, r)
				return
			}
			if r.Header.Get(":protocol") != "websocket" {
				// We bridge WebSocket only.
				metric.WSTunnel("bad_protocol")
				http.Error(w, "Not Implemented", http.StatusNotImplemented)
				return
			}
			h.ServeHTTP(w, wsh2.Normalize(r))
		})
	})
}
