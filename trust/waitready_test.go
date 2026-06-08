package trust

import (
	"context"
	"testing"
	"time"
)

// applyCA loads a freshly-generated edge CA into the manager's pool.
func applyCA(t *testing.T, m *Manager) {
	t.Helper()
	caPEM, _ := caPEMFor(t)
	if _, err := m.apply(Bundle{Generation: 1, CAPEM: caPEM, CAID: "a"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
}

func TestWaitReady_AlreadyLoaded(t *testing.T) {
	m := NewManager()
	applyCA(t, m)
	start := time.Now()
	if !m.WaitReady(context.Background(), 5*time.Second) {
		t.Fatal("WaitReady should return true when the pool is already loaded")
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Errorf("WaitReady should return immediately when already loaded, took %v", d)
	}
}

func TestWaitReady_ZeroTimeoutReturnsCurrentState(t *testing.T) {
	m := NewManager()
	if m.WaitReady(context.Background(), 0) {
		t.Error("WaitReady(0) on an unloaded manager must return false immediately")
	}
	applyCA(t, m)
	if !m.WaitReady(context.Background(), 0) {
		t.Error("WaitReady(0) after load must return true")
	}
}

// TestWaitReady_TimeoutFailStatic is the load-bearing guarantee: if the pool never
// loads (CP down at boot), WaitReady must return false on its own deadline and NOT
// block forever — the caller then reports Ready and serves CIDR-only (fail-static).
func TestWaitReady_TimeoutFailStatic(t *testing.T) {
	m := NewManager() // never loaded
	start := time.Now()
	if m.WaitReady(context.Background(), 150*time.Millisecond) {
		t.Error("WaitReady must return false when the pool never loads")
	}
	d := time.Since(start)
	if d < 100*time.Millisecond {
		t.Errorf("WaitReady returned before its deadline (%v) — it must actually wait", d)
	}
	if d > 2*time.Second {
		t.Errorf("WaitReady blocked well past its deadline (%v) — it must be bounded", d)
	}
}

func TestWaitReady_LoadsDuringWait(t *testing.T) {
	m := NewManager()
	caPEM, _ := caPEMFor(t)
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = m.apply(Bundle{Generation: 1, CAPEM: caPEM, CAID: "a"})
	}()
	start := time.Now()
	if !m.WaitReady(context.Background(), 5*time.Second) {
		t.Fatal("WaitReady should observe a pool that loads during the wait")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("WaitReady took too long to observe the mid-wait load (%v)", d)
	}
}

func TestWaitReady_ContextCancel(t *testing.T) {
	m := NewManager() // never loaded
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if m.WaitReady(ctx, 10*time.Second) {
		t.Error("WaitReady must return false when ctx is cancelled before load")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("WaitReady did not honor ctx cancellation promptly (%v)", d)
	}
}
