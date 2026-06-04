package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/edgecp"
)

func TestProvidedGeneration(t *testing.T) {
	// A temp cert file with a known mtime for the fallback cases.
	cert := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(cert, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(1_700_000_000, 0)
	if err := os.Chtimes(cert, mtime, mtime); err != nil {
		t.Fatal(err)
	}

	t.Run("env wins", func(t *testing.T) {
		t.Setenv("EDGE_CA_PROVIDED_GENERATION", "42")
		if got := providedGeneration(cert); got != 42 {
			t.Errorf("got %d, want 42", got)
		}
	})

	t.Run("env=0 is rejected, falls back to mtime", func(t *testing.T) {
		// 0 parses but defeats the core's anti-rollback guard — must NOT be returned.
		t.Setenv("EDGE_CA_PROVIDED_GENERATION", "0")
		if got := providedGeneration(cert); got != uint64(mtime.Unix()) {
			t.Errorf("env=0 must fall through to mtime, got %d", got)
		}
	})

	t.Run("env unparseable falls back to mtime", func(t *testing.T) {
		t.Setenv("EDGE_CA_PROVIDED_GENERATION", "abc")
		if got := providedGeneration(cert); got != uint64(mtime.Unix()) {
			t.Errorf("got %d, want mtime %d", got, mtime.Unix())
		}
	})

	t.Run("no env, missing cert -> 1", func(t *testing.T) {
		os.Unsetenv("EDGE_CA_PROVIDED_GENERATION")
		if got := providedGeneration(filepath.Join(t.TempDir(), "nope.crt")); got != 1 {
			t.Errorf("got %d, want 1", got)
		}
	})

	// The function must NEVER return 0 (a replayed-older bundle would beat it).
	t.Run("never zero", func(t *testing.T) {
		t.Setenv("EDGE_CA_PROVIDED_GENERATION", "00")
		if got := providedGeneration(cert); got == 0 {
			t.Error("providedGeneration must never return 0")
		}
	})
}

func TestDuplicateEdgeID(t *testing.T) {
	if got := duplicateEdgeID(map[string]edgecp.Entry{
		"t1": {ID: "edge-a"},
		"t2": {ID: "edge-b"},
		"t3": {}, // cert-only token, no id
		"t4": {}, // another empty id — not a collision
	}); got != "" {
		t.Errorf("unique ids must not report a duplicate, got %q", got)
	}
	if got := duplicateEdgeID(map[string]edgecp.Entry{
		"t1": {ID: "dup"},
		"t2": {ID: "dup"},
	}); got != "dup" {
		t.Errorf("duplicate id must be reported, got %q", got)
	}
}

func TestCadenceWindowAndCheck(t *testing.T) {
	// N reads span N-1 gaps (the off-by-one the review caught).
	if got := cadenceWindow(30*time.Second, 2); got != 30*time.Second {
		t.Errorf("cadenceWindow(30s,2) = %v, want 30s", got)
	}
	if got := cadenceWindow(60*time.Second, 3); got != 120*time.Second {
		t.Errorf("cadenceWindow(60s,3) = %v, want 120s", got)
	}
	// window must cover >= 2 scrapes AND >= refresh.
	if err := checkCadence(120*time.Second, 15*time.Second, 60*time.Second); err != nil {
		t.Errorf("ample window must pass: %v", err)
	}
	if err := checkCadence(20*time.Second, 15*time.Second, 60*time.Second); err == nil {
		t.Error("window < refresh must be refused")
	}
	if err := checkCadence(20*time.Second, 15*time.Second, 10*time.Second); err == nil {
		t.Error("window < 2×scrape must be refused")
	}
}
