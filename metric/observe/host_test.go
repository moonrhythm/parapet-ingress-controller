package observe

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestHostRatelimitRequest(t *testing.T) {
	const host = "host-ratelimit-observer-test.example.com"
	HostRatelimitRequest(host)
	HostRatelimitRequest(host)
	c := hostRatelimitVec.With(prometheus.Labels{"host": host})
	assert.Equal(t, 2.0, testutil.ToFloat64(c))
}

func TestRejectedRequest(t *testing.T) {
	const reason = "host_rps_observer_test"
	RejectedRequest(reason)
	RejectedRequest(reason)
	c := rejectedVec.With(prometheus.Labels{"reason": reason})
	assert.Equal(t, 2.0, testutil.ToFloat64(c))
}
