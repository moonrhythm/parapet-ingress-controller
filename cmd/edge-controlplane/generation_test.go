package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
