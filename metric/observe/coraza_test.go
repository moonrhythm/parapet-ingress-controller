package observe

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func corazaMatchCount(t *testing.T, ruleID, severity, scope, zone string) float64 {
	t.Helper()
	h, err := _corazaMatch.vec.GetMetricWith(prometheus.Labels{"rule_id": ruleID, "severity": severity, "scope": scope, "zone": zone})
	require.NoError(t, err)
	var m dto.Metric
	require.NoError(t, h.(prometheus.Metric).Write(&m))
	return m.GetCounter().GetValue()
}

func TestCorazaMatch(t *testing.T) {
	const scope = "coraza-match-test"
	onMatch := CorazaMatch(scope, "ns/coraza-match-test")

	onMatch(942100, "critical")
	onMatch(942100, "critical")
	onMatch(913100, "warning")

	assert.EqualValues(t, 2, corazaMatchCount(t, "942100", "critical", scope, "ns/coraza-match-test"))
	assert.EqualValues(t, 1, corazaMatchCount(t, "913100", "warning", scope, "ns/coraza-match-test"))
}

func TestCorazaMatchScopesAreDistinct(t *testing.T) {
	global := CorazaMatch("coraza-match-scope-g", "")
	zone := CorazaMatch("coraza-match-scope-z", "ns/coraza-match-scope-z")

	global(949110, "critical")
	zone(949110, "critical")
	zone(949110, "critical")

	assert.EqualValues(t, 1, corazaMatchCount(t, "949110", "critical", "coraza-match-scope-g", ""))
	assert.EqualValues(t, 2, corazaMatchCount(t, "949110", "critical", "coraza-match-scope-z", "ns/coraza-match-scope-z"))
}

// TestCorazaMatchZonesAreDistinct pins the reason the zone label exists:
// Coraza rule ids are CRS ids shared by every zone, so two zones firing the
// same rule must still be attributable to their own series.
func TestCorazaMatchZonesAreDistinct(t *testing.T) {
	a := CorazaMatch("coraza-match-zone", "ns/zone-a")
	b := CorazaMatch("coraza-match-zone", "ns/zone-b")

	a(942100, "critical")
	b(942100, "critical")
	b(942100, "critical")

	assert.EqualValues(t, 1, corazaMatchCount(t, "942100", "critical", "coraza-match-zone", "ns/zone-a"))
	assert.EqualValues(t, 2, corazaMatchCount(t, "942100", "critical", "coraza-match-zone", "ns/zone-b"))
}
