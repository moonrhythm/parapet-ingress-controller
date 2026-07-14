package metric

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func corazaMatchCount(t *testing.T, ruleID, severity, scope, zone string) float64 {
	t.Helper()
	h, err := _coraza.vec.GetMetricWith(prometheus.Labels{"rule_id": ruleID, "severity": severity, "scope": scope, "zone": zone})
	require.NoError(t, err)
	var m dto.Metric
	require.NoError(t, h.(prometheus.Metric).Write(&m))
	return m.GetCounter().GetValue()
}

// TestCorazaMatchZonesAreDistinct is the controller-side sibling of
// observe.TestCorazaMatchZonesAreDistinct: it pins that CorazaMatch records the
// zone value onto the zone label of _coraza.vec (through the handle cache), so
// two zones firing the same shared CRS rule id stay attributable to their own
// series. Without it only the edge recorder's zone label is under test.
func TestCorazaMatchZonesAreDistinct(t *testing.T) {
	const scope = "coraza-match-zone"

	CorazaMatch(942100, "critical", scope, "ns/zone-a")
	CorazaMatch(942100, "critical", scope, "ns/zone-b")
	CorazaMatch(942100, "critical", scope, "ns/zone-b")

	assert.EqualValues(t, 1, corazaMatchCount(t, "942100", "critical", scope, "ns/zone-a"))
	assert.EqualValues(t, 2, corazaMatchCount(t, "942100", "critical", scope, "ns/zone-b"))
}

// TestCorazaMatchGlobalZoneEmpty pins the scope=global convention: zone is "".
func TestCorazaMatchGlobalZoneEmpty(t *testing.T) {
	const scope = "coraza-match-global"

	CorazaMatch(949110, "unknown", scope, "")

	assert.EqualValues(t, 1, corazaMatchCount(t, "949110", "unknown", scope, ""))
}
