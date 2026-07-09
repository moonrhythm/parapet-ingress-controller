package observe

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

// _wsUpstream counts edge→core WebSocket handshake outcomes. Unlike the WAF /
// Coraza match counters this is a NEW metric name — the metric package never
// registers it — so it registers eagerly at init like the ratelimit/cache
// observers, with no collision hazard.
var _wsUpstream *prometheus.CounterVec

func init() {
	_wsUpstream = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "edge_ws_upstream",
	}, []string{"protocol", "result"})
	prom.Registry().MustRegister(_wsUpstream)
}

// WSUpstream records one edge→core WebSocket tunnel outcome as
// parapet_edge_ws_upstream{protocol,result}:
//   - ("h2","ok")            extended CONNECT to the core succeeded (the core
//     answered 200 and the session spliced, or relayed a
//     non-200 refusal — the h2 hop itself worked).
//   - ("http1","fallback")   the tunnel was NOT used; the request fell back to the
//     HTTP/1.1 upgrade path (core doesn't advertise extended
//     CONNECT — GODEBUG=http2xconnect=1 missing / old core —
//     or a pre-commit transport failure). The "core lost its
//     GODEBUG" alarm.
//   - ("h2","error")         the tunnel attempt failed AFTER bytes were committed to
//     the client (101 written / hijacked), so it could not
//     fall back and the client session is broken.
//
// Both label values are fixed operator-set strings, never request input, so the
// series stays bounded.
func WSUpstream(protocol, result string) {
	_wsUpstream.WithLabelValues(protocol, result).Inc()
}
