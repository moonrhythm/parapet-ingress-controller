package controller

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/moonrhythm/parapet-ingress-controller/proxy"
)

// readinessProbe serves /healthz?ready=1 through the controller's real Healthz middleware
// and reports whether it answers Ready (200) vs NotReady (503). The request uses an IP
// host because the middleware only intercepts IP-host probes (k8s hits the pod IP) and
// passes hostname traffic through.
func readinessProbe(t *testing.T, ctrl *Controller) bool {
	t.Helper()
	h := ctrl.Healthz().ServeHandler(http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/healthz?ready=1", nil))
	return rec.Code == http.StatusOK
}

// TestFirstReload_TrustGateRunsBeforeReady pins the ordering the edge-trust readiness gate
// depends on: firstReload must invoke WaitTrustReady BEFORE flipping the controller to
// Ready, so the edge isn't routed here until the trust pool has had its chance to load.
// This is the regression guard for the main.go wiring, where `go ctrl.Watch()` must not
// race ahead of the hook install (firstReload reads ctrl.WaitTrustReady).
func TestFirstReload_TrustGateRunsBeforeReady(t *testing.T) {
	ctrl := New("", proxy.New())

	if readinessProbe(t, ctrl) {
		t.Fatal("controller must start NotReady")
	}

	var hookRan, readyWhenHookRan bool
	ctrl.WaitTrustReady = func() {
		hookRan = true
		readyWhenHookRan = readinessProbe(t, ctrl) // readiness observed AT the gate
	}

	ctrl.firstReload()

	if !hookRan {
		t.Fatal("firstReload must invoke WaitTrustReady")
	}
	if readyWhenHookRan {
		t.Error("WaitTrustReady ran AFTER the controller was marked Ready — the gate is ineffective " +
			"(it must run before SetReady so the edge isn't routed during the cold-start window)")
	}
	if !readinessProbe(t, ctrl) {
		t.Error("controller must be Ready after firstReload")
	}
}

// TestFirstReload_NoTrustGate confirms the hook is optional: with no WaitTrustReady set
// (auto-trust off), firstReload still completes and reports Ready.
func TestFirstReload_NoTrustGate(t *testing.T) {
	ctrl := New("", proxy.New())
	if readinessProbe(t, ctrl) {
		t.Fatal("controller must start NotReady")
	}
	ctrl.firstReload()
	if !readinessProbe(t, ctrl) {
		t.Error("controller must be Ready after firstReload when no trust gate is installed")
	}
}
