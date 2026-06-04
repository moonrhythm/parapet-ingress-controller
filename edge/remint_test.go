package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testCoord builds a coordinator against a fake CP that signs CSRs, with no real jitter
// so runOnce is fast and deterministic.
func testCoord(t *testing.T, cfg RemintConfig) (*RemintCoordinator, *ClientCertStore) {
	t.Helper()
	srv, _ := fakeEdgeCP(t)
	cp, err := NewCpClient(srv.URL, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	store := NewClientCertStore()
	cfg.Jitter = 1 // 1ns → fullJitter returns 0 (no sleep)
	cfg.BackoffBase = 1
	return NewRemintCoordinator(cp, store, cfg), store
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

// Observe must NOT trigger when the target is unknown (""), the held leaf is unknown
// (""), or the edge has already converged (target == live). These would hot-loop.
func TestObserveNoOps(t *testing.T) {
	coord, store := testCoord(t, RemintConfig{})
	reqs := 0
	// Re-point at a request-counting CP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs++
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	cp, _ := NewCpClient(srv.URL, "tok", nil)
	coord.cp = cp

	coord.Observe("")            // unknown target → no-op
	coord.Observe("some-target") // live=="" (no cert held) → no-op
	time.Sleep(20 * time.Millisecond)
	if reqs != 0 {
		t.Errorf("Observe must not mint when target/live unknown, got %d requests", reqs)
	}
	_ = store
}

// Observe triggers a proactive re-mint when the CP target differs from the held leaf.
func TestObserveTriggersProactive(t *testing.T) {
	coord, store := testCoord(t, RemintConfig{})
	// Pre-load a cert so store.CAID() is non-empty (the "live" side).
	if _, _ = RefreshEdgeCertOnce(coord.cp, store, "timer"); !store.Loaded() {
		t.Fatal("pre-mint failed")
	}
	live := store.CAID()
	if live == "" {
		t.Fatal("pre-minted cert has no ca_id")
	}
	// A DIFFERENT observed target must trigger a re-mint (request count rises).
	coord.Observe("a-different-target")
	waitFor(t, func() bool { return !coordInFlight(coord) && store.CAID() == live })
	// (the fake CP always signs the same ca_id, so the edge stays at `live`; the point
	// is that a mint WAS attempted — verified via the proactive breaker climbing.)
	coord.mu.Lock()
	noConverge := coord.proactiveNoConverge
	coord.mu.Unlock()
	if noConverge == 0 {
		t.Error("a proactive mint that didn't reach the (fake) target should increment proactiveNoConverge")
	}
}

// K reactive ok-mints that don't change ca_id open the reactive breaker. Reaching the
// CP target does NOT reset it (the core may still reject); only a genuine ca_id FLIP does.
func TestReactiveBreaker(t *testing.T) {
	coord, store := testCoord(t, RemintConfig{BreakerK: 2})
	RefreshEdgeCertOnce(coord.cp, store, "timer") // store now at ca_id Z
	z := store.CAID()

	// Two reactive no-flip mints (the CP keeps signing Z) → breaker opens.
	coord.runOnce("reactive")
	coord.runOnce("reactive")
	coord.mu.Lock()
	open := time.Now().Before(coord.reactiveBreakerEnd)
	noFlip := coord.reactiveNoFlip
	coord.mu.Unlock()
	if !open || noFlip < 2 {
		t.Fatalf("reactive breaker should be OPEN after 2 no-flip mints (noFlip=%d, open=%v)", noFlip, open)
	}

	// Edge already AT the target but the core keeps rejecting (after==target, no flip):
	// this must NOT reset — re-minting the same ca_id can't fix a core-side reject.
	coord.Observe(z) // lastTarget = z (== live; converged, no trigger)
	coord.runOnce("reactive")
	coord.mu.Lock()
	stillClimbing := coord.reactiveNoFlip
	coord.mu.Unlock()
	if stillClimbing < noFlip {
		t.Errorf("reaching the target must NOT reset the reactive breaker (was %d, now %d)", noFlip, stillClimbing)
	}

	// A genuine ca_id FLIP (new trust material) resets it.
	other := "a-different-ca-id"
	store.caid.Store(&other) // pretend the held leaf is now a different CA set
	coord.runOnce("reactive")
	coord.mu.Lock()
	reset := coord.reactiveNoFlip
	rOpen := time.Now().Before(coord.reactiveBreakerEnd)
	coord.mu.Unlock()
	if reset != 0 || rOpen {
		t.Errorf("a genuine ca_id flip must reset+close the reactive breaker (noFlip=%d, open=%v)", reset, rOpen)
	}
}

// J proactive ok-mints that don't reach the observed target open the proactive breaker,
// WITHOUT touching the reactive breaker.
func TestProactiveBreaker(t *testing.T) {
	coord, store := testCoord(t, RemintConfig{ProactiveJ: 2})
	RefreshEdgeCertOnce(coord.cp, store, "timer") // store at Z
	coord.mu.Lock()
	coord.lastTarget = "unreachable-target" // the fake CP only ever signs Z
	coord.mu.Unlock()

	coord.runOnce("proactive")
	coord.runOnce("proactive")
	coord.mu.Lock()
	pOpen := time.Now().Before(coord.proactiveBreakerEnd)
	n := coord.proactiveNoConverge
	rOpen := time.Now().Before(coord.reactiveBreakerEnd)
	coord.mu.Unlock()
	if !pOpen || n < 2 {
		t.Fatalf("proactive breaker should open after 2 non-converging mints (n=%d, open=%v)", n, pOpen)
	}
	if rOpen {
		t.Error("proactive failures must NOT open the reactive breaker")
	}
}

func TestChooseSleep(t *testing.T) {
	if got := chooseSleep(2*time.Second, 7*time.Second); got != 7*time.Second {
		t.Errorf("retryAfter > backoff: %v, want 7s", got)
	}
	if got := chooseSleep(5*time.Second, 2*time.Second); got != 5*time.Second {
		t.Errorf("backoff >= retryAfter: %v, want 5s", got)
	}
	if got := chooseSleep(3*time.Second, 0); got != 3*time.Second {
		t.Errorf("no retryAfter: %v, want 3s", got)
	}
}

// A non-ok mint (CP down) is the BACKOFF path, never breaker evidence — a transient
// outage during a rotation must not open the breaker while the edge presents a rejected leaf.
func TestNonOkDoesNotOpenBreaker(t *testing.T) {
	coord, _ := testCoord(t, RemintConfig{BreakerK: 2})
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(down.Close)
	cp, _ := NewCpClient(down.URL, "tok", nil)
	coord.cp = cp

	for i := 0; i < 4; i++ {
		coord.runOnce("reactive")
	}
	coord.mu.Lock()
	open := time.Now().Before(coord.reactiveBreakerEnd)
	noFlip := coord.reactiveNoFlip
	coord.mu.Unlock()
	if open || noFlip != 0 {
		t.Errorf("transient failures must not feed the breaker (noFlip=%d, open=%v)", noFlip, open)
	}
}

// MaybeRenew mints when nothing is held yet (the startup mint failed / never ran).
func TestMaybeRenewMintsWhenEmpty(t *testing.T) {
	coord, store := testCoord(t, RemintConfig{})
	coord.MaybeRenew()
	waitFor(t, func() bool { return store.Loaded() })
}

// Single-flight: many concurrent Triggers coalesce — at most one mint runs at a time.
func TestSingleFlight(t *testing.T) {
	coord, store := testCoord(t, RemintConfig{})
	RefreshEdgeCertOnce(coord.cp, store, "timer")
	var concurrent, maxConcurrent int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		coord.mu.Lock()
		concurrent++
		if concurrent > maxConcurrent {
			maxConcurrent = concurrent
		}
		coord.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		coord.mu.Lock()
		concurrent--
		coord.mu.Unlock()
		http.Error(w, "x", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	cp, _ := NewCpClient(srv.URL, "tok", nil)
	coord.cp = cp

	for i := 0; i < 10; i++ {
		go coord.Trigger("reactive")
	}
	time.Sleep(100 * time.Millisecond)
	coord.mu.Lock()
	mc := maxConcurrent
	coord.mu.Unlock()
	if mc > 1 {
		t.Errorf("single-flight violated: %d concurrent mints", mc)
	}
}

func coordInFlight(c *RemintCoordinator) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inFlight
}
