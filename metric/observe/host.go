package observe

import (
	"sync"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

// Host-limiter overflow series (parapet_host_ratelimit_requests,
// parapet_rejected_requests) are registered LAZILY on first call. The
// controller already registers them in metric's init; eager registration here
// would panic at controller startup. Only the edge (which never imports metric)
// mints them from this package. Same names and labels as metric so dashboards
// and CP merge stay one family.
var (
	hostRatelimitOnce sync.Once
	hostRatelimitVec  *prometheus.CounterVec

	rejectedOnce sync.Once
	rejectedVec  *prometheus.CounterVec
)

func hostRatelimitRegister() {
	hostRatelimitOnce.Do(func() {
		hostRatelimitVec = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: prom.Namespace,
			Name:      "host_ratelimit_requests",
		}, []string{"host"})
		prom.Registry().MustRegister(hostRatelimitVec)
	})
}

func rejectedRegister() {
	rejectedOnce.Do(func() {
		rejectedVec = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: prom.Namespace,
			Name:      "rejected_requests",
		}, []string{"reason"})
		prom.Registry().MustRegister(rejectedVec)
	})
}

// HostRatelimitRequest increments parapet_host_ratelimit_requests{host}. host
// must already be collapsed (hostlabel.Of) — never raw request input.
func HostRatelimitRequest(host string) {
	hostRatelimitRegister()
	hostRatelimitVec.WithLabelValues(host).Inc()
}

// RejectedRequest increments parapet_rejected_requests{reason}. reason is a
// small bounded set (never host-derived).
func RejectedRequest(reason string) {
	rejectedRegister()
	rejectedVec.WithLabelValues(reason).Inc()
}
