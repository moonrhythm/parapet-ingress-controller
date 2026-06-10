package converge_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The convergence reader pulls in the Prometheus HTTP API client. That dependency — and
// the converge package itself — must NEVER reach the serving / issuance / trust request
// path, so a Prometheus outage can't break cert issuance or the trust bundle. This is the
// mechanical guarantee (a test, not a comment): the serving packages must not transitively
// import edgecp/converge or client_golang/api.
//
// cmd/edge-controlplane is deliberately NOT listed — it HOSTS the converge-status CLI in a
// run-once exec branch (the whole binary links the package, but the issuance HANDLERS in
// the edgecp package never call it; that handler-package boundary is what this enforces).
func TestServingPathDoesNotImportConvergeOrPromClient(t *testing.T) {
	const (
		convergePkg = "github.com/moonrhythm/parapet-ingress-controller/edgecp/converge"
		promAPIPkg  = "github.com/prometheus/client_golang/api"
	)
	servingPkgs := []string{
		"github.com/moonrhythm/parapet-ingress-controller/edgecp", // the CP issuance/trust handlers
		"github.com/moonrhythm/parapet-ingress-controller/edge",   // the edge data plane
		"github.com/moonrhythm/parapet-ingress-controller/cmd/edge-proxy",
		"github.com/moonrhythm/parapet-ingress-controller/trust", // the core trust manager
		"github.com/moonrhythm/parapet-ingress-controller/metric",
		"github.com/moonrhythm/parapet-ingress-controller/metric/observe",
	}
	for _, pkg := range servingPkgs {
		out, err := exec.Command("go", "list", "-deps", pkg).Output()
		if err != nil {
			t.Fatalf("go list -deps %s: %v", pkg, err)
		}
		deps := string(out)
		for _, forbidden := range []string{convergePkg, promAPIPkg} {
			for _, line := range strings.Split(deps, "\n") {
				if strings.TrimSpace(line) == forbidden {
					t.Errorf("%s transitively imports %s — the serving path must stay decoupled from the Prometheus reader", pkg, forbidden)
				}
			}
		}
	}
}
