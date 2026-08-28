package metric

import (
	"net/http"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/moonrhythm/parapet-ingress-controller/hostlabel"
)

// HostLabel returns host if the router serves it, else hostlabel.Other. A
// nil isKnownHost (e.g. in tests) passes the host through unchanged.
func HostLabel(host string, isKnownHost func(host string) bool) string {
	return hostlabel.Of(host, isKnownHost)
}

var _rejected = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: prom.Namespace,
	Name:      "rejected_requests",
}, []string{"reason"})

func init() {
	prom.Registry().MustRegister(_rejected)
}

// RejectedRequest records a request rejected at the edge, by reason. `reason` is
// a small bounded set (never host-derived), so this metric's cardinality can't
// be driven by request input — unlike `requests`, it stays safe to scrape under
// a flood.
func RejectedRequest(reason string) {
	_rejected.WithLabelValues(reason).Inc()
}

// rejectReason maps an edge-rejection HTTP status to a bounded reason label, or
// "" if the status isn't a tracked rejection. The caller must only apply it when
// the request did NOT reach a backend, so a backend responding with one of these
// codes isn't miscounted as an ingress rejection. host_limit and host_rps are
// recorded directly at the host-concurrency / host-RPS limiters (they
// short-circuit before the request metric runs), not here.
// edgeRejectReason returns the reason for a request rejected at the edge, or ""
// if it isn't a tracked rejection. reachedBackend gates it: once the request has
// been proxied, the status is the backend's own response, not an ingress
// rejection, so nothing is counted.
func edgeRejectReason(reachedBackend bool, status int) string {
	if reachedBackend {
		return ""
	}
	return rejectReason(status)
}

func rejectReason(status int) string {
	switch status {
	case http.StatusNotFound: // 404 — no matching ingress route
		return "no_route"
	case http.StatusForbidden: // 403 — allow-remote
		return "forbidden"
	case http.StatusUnauthorized: // 401 — basic/forward auth
		return "unauthorized"
	case http.StatusRequestEntityTooLarge: // 413 — body limit
		return "body_limit"
	case http.StatusTooManyRequests: // 429 — per-route rate limit
		return "rate_limit"
	default:
		return ""
	}
}
