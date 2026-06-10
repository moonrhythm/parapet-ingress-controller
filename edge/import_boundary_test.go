package edge_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The metric package init-materializes the CONTROLLER's core-trust alerting
// series (metric/trust.go pre-resolves its gauge/counter handles), so any binary
// that links it exports trust_warmstart_active, trust_bundle_age_seconds, etc.
// as constant zeros. On the edge those bogus series would dilute the fleet-wide
// aggregations they exist to alert on (e.g. avg(trust_bundle_age_seconds)).
// That is why the shared per-request observers live in the LEAF package
// metric/observe — and this test is the mechanical guarantee the edge binaries
// stay on the leaf (the boundary regressed once, unnoticed, before this test).
func TestEdgeBinariesDoNotImportMetric(t *testing.T) {
	const metricPkg = "github.com/moonrhythm/parapet-ingress-controller/metric"
	for _, pkg := range []string{
		"github.com/moonrhythm/parapet-ingress-controller/cmd/edge-proxy",
		"github.com/moonrhythm/parapet-ingress-controller/cmd/edge-controlplane",
	} {
		out, err := exec.Command("go", "list", "-deps", pkg).Output()
		if err != nil {
			t.Fatalf("go list -deps %s: %v", pkg, err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.TrimSpace(line) == metricPkg {
				t.Errorf("%s transitively imports %s — edge binaries must use metric/observe (the leaf) so the controller's init-materialized core-trust series stay off the edge's /metrics", pkg, metricPkg)
			}
		}
	}
}
