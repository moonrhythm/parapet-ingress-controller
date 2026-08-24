package metric

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestBackendBadAddr(t *testing.T) {
	labels := prometheus.Labels{
		"service_type":      "ClusterIP",
		"service_namespace": "ns",
		"service_name":      "svc-badaddr",
	}
	c := _backendBadAddr.vec.With(labels)
	before := testutil.ToFloat64(c)
	BackendBadAddr("ClusterIP", "ns", "svc-badaddr")
	BackendBadAddr("ClusterIP", "ns", "svc-badaddr")
	assert.Equal(t, before+2, testutil.ToFloat64(c), "every mark counts, including a re-mark")

	other := _backendBadAddr.vec.With(prometheus.Labels{
		"service_type":      "ClusterIP",
		"service_namespace": "ns",
		"service_name":      "svc-other",
	})
	otherBefore := testutil.ToFloat64(other)
	BackendBadAddr("ClusterIP", "ns", "svc-other")
	assert.Equal(t, otherBefore+1, testutil.ToFloat64(other), "series are per-Service")
	assert.Equal(t, before+2, testutil.ToFloat64(c), "other Service does not move this series")
}
