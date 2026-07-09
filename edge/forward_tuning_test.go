package edge

import (
	"net/http"
	"testing"

	"github.com/moonrhythm/parapet/pkg/upstream"
)

// ForwarderTuning must thread the per-host connection ceiling into whichever
// transport NewForwarder selects, so EDGE_UPSTREAM_MAX_CONNS_PER_HOST is a real
// hard cap on each path (and a 0 idle pool falls back to parapet's default 32).
func TestForwarderTuning_AppliesToEveryTransport(t *testing.T) {
	const (
		maxConns = 7
		maxIdle  = 3
	)
	tuning := ForwarderTuning{MaxConnsPerHost: maxConns, MaxIdleConnsPerHost: maxIdle}

	t.Run("plaintext HTTP/1.1", func(t *testing.T) {
		f := NewForwarder("core:80", false, false, "", tuning, nil, nil, false)
		tr := f.rp.Transport.(*upstream.HTTPTransport)
		if tr.MaxConn != maxConns {
			t.Fatalf("MaxConn = %d, want %d", tr.MaxConn, maxConns)
		}
		if tr.MaxIdleConns != maxIdle {
			t.Fatalf("MaxIdleConns = %d, want %d", tr.MaxIdleConns, maxIdle)
		}
	})

	t.Run("plaintext h2c Upgrade fallback", func(t *testing.T) {
		f := NewForwarder("core:80", false, true, "", tuning, nil, nil, false)
		tr := f.rp.Transport.(*upstream.H2CTransport)
		if tr.HTTPTransport == nil {
			t.Fatal("H2CTransport.HTTPTransport (Upgrade fallback) not wired")
		}
		if got := tr.HTTPTransport.MaxConnsPerHost; got != maxConns {
			t.Fatalf("fallback MaxConnsPerHost = %d, want %d", got, maxConns)
		}
		if got := tr.HTTPTransport.MaxIdleConnsPerHost; got != maxIdle {
			t.Fatalf("fallback MaxIdleConnsPerHost = %d, want %d", got, maxIdle)
		}
	})

	t.Run("re-encrypt h2", func(t *testing.T) {
		f := NewForwarder("core:443", true, true, "", tuning, nil, nil, false)
		h2 := f.rp.Transport.(*h2TLSTransport).h2.(*http.Transport)
		if h2.MaxConnsPerHost != maxConns {
			t.Fatalf("h2 MaxConnsPerHost = %d, want %d", h2.MaxConnsPerHost, maxConns)
		}
		if h2.MaxIdleConnsPerHost != maxIdle {
			t.Fatalf("h2 MaxIdleConnsPerHost = %d, want %d", h2.MaxIdleConnsPerHost, maxIdle)
		}
	})

	t.Run("re-encrypt HTTP/1.1", func(t *testing.T) {
		f := NewForwarder("core:443", true, false, "", tuning, nil, nil, false)
		tr := f.rp.Transport.(*upstream.HTTPSTransport)
		if tr.MaxConn != maxConns {
			t.Fatalf("MaxConn = %d, want %d", tr.MaxConn, maxConns)
		}
		if tr.MaxIdleConns != maxIdle {
			t.Fatalf("MaxIdleConns = %d, want %d", tr.MaxIdleConns, maxIdle)
		}
	})
}

// The zero value keeps the historical behavior: no connection ceiling, idle pool
// defaulting to parapet's 32.
func TestForwarderTuning_ZeroValueDefaults(t *testing.T) {
	if got := (ForwarderTuning{}).idle(); got != defaultMaxIdleConnsPerHost {
		t.Fatalf("zero idle() = %d, want %d", got, defaultMaxIdleConnsPerHost)
	}
	f := NewForwarder("core:80", false, false, "", ForwarderTuning{}, nil, nil, false)
	tr := f.rp.Transport.(*upstream.HTTPTransport)
	if tr.MaxConn != 0 {
		t.Fatalf("MaxConn = %d, want 0 (unlimited)", tr.MaxConn)
	}
	if tr.MaxIdleConns != defaultMaxIdleConnsPerHost {
		t.Fatalf("MaxIdleConns = %d, want %d", tr.MaxIdleConns, defaultMaxIdleConnsPerHost)
	}
}
