// Package hostrps is the pre-WAF per-Host arrival-rate fuse used by the
// controller and the edge. It does not import metric: edge binaries must stay
// off that package (see edge/import_boundary_test.go). Callers wire their own
// overflow counters via OnLimited.
package hostrps

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/header"
	"github.com/moonrhythm/parapet/pkg/ratelimit"

	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
)

// collapsedHost is the shared bucket for Hosts isKnownHost rejects (random-Host
// floods and host-less catch-all traffic). Same sentinel as metric.HostLabel.
const collapsedHost = "other"

// New returns a 1s epoch-aligned fixed-window limiter of `rate` admits per Host
// per replica, or nil when rate <= 0. Overflow is 503 with a ceiled Retry-After.
// isKnownHost may be nil (every Host is its own bucket — tests only).
func New(rate int, isKnownHost func(string) bool, onLimited func(string)) parapet.Middleware {
	if rate <= 0 {
		return nil
	}
	slog.Info("setting up host RPS limit", "rate", rate, "window", "1s")
	return ratelimit.RateLimiter{
		Name:     "host-rps",
		Observe:  observe.RateLimit("host-rps"),
		Strategy: &ratelimit.FixedWindowStrategy{Max: rate, Size: time.Second},
		Key: func(r *http.Request) string {
			return bucket(r.Host, isKnownHost)
		},
		ExceededHandler: func(w http.ResponseWriter, r *http.Request, after time.Duration) {
			if after > 0 {
				// Ceil to >= 1: truncation would emit "Retry-After: 0" for a
				// 1s window (After is in (0,1s]) and a compliant client would
				// retry into another denial. Same formula as ratelimitrule.
				secs := int64((after + time.Second - 1) / time.Second)
				header.Set(w.Header(), header.RetryAfter, strconv.FormatInt(secs, 10))
			}
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			if onLimited != nil {
				onLimited(bucket(r.Host, isKnownHost))
			}
		},
	}
}

func bucket(host string, isKnownHost func(string) bool) string {
	if isKnownHost == nil || isKnownHost(host) {
		return host
	}
	return collapsedHost
}
