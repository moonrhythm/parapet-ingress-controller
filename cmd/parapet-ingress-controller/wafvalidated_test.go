package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildWAFValidatedProxy(t *testing.T) {
	t.Parallel()

	reqFrom := func(remoteAddr string, cs *tls.ConnectionState) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://app/", nil)
		r.RemoteAddr = remoteAddr
		r.TLS = cs
		return r
	}

	t.Run("empty and false disable the skip", func(t *testing.T) {
		for _, spec := range []string{"", "false", "  "} {
			pred, err := buildWAFValidatedProxy(spec, nil)
			require.NoError(t, err, "spec=%q", spec)
			assert.Nil(t, pred, "spec=%q", spec)
		}
	})

	t.Run("true is refused", func(t *testing.T) {
		_, err := buildWAFValidatedProxy("true", nil)
		require.Error(t, err)
	})

	t.Run("true and false are refused as list tokens", func(t *testing.T) {
		// A lone surviving "true" token would rejoin into exactly "true" and
		// hit trustcidr.Parse's whole-spec special case (parapet.Trusted(), a
		// match-everything predicate) — a one-character typo must not become a
		// silent blanket WAF skip.
		verify := func(*tls.ConnectionState) bool { return true }
		for _, spec := range []string{"true,", ",true", " true ,", "edge-mtls,true", "edge-mtls,false", "10.0.0.0/8,true"} {
			_, err := buildWAFValidatedProxy(spec, verify)
			require.Error(t, err, "spec=%q", spec)
		}
	})

	t.Run("edge-mtls without auto-trust is a misconfiguration", func(t *testing.T) {
		_, err := buildWAFValidatedProxy("edge-mtls", nil)
		require.Error(t, err)
	})

	t.Run("edge-mtls consults the verifier with the request TLS state", func(t *testing.T) {
		var got *tls.ConnectionState
		verdict := true
		pred, err := buildWAFValidatedProxy("edge-mtls", func(cs *tls.ConnectionState) bool {
			got = cs
			return verdict
		})
		require.NoError(t, err)
		require.NotNil(t, pred)

		cs := &tls.ConnectionState{}
		assert.True(t, pred(reqFrom("192.168.1.1:1234", cs)))
		assert.Same(t, cs, got)
		verdict = false
		assert.False(t, pred(reqFrom("192.168.1.1:1234", cs)))
	})

	t.Run("cidr matches the immediate peer", func(t *testing.T) {
		pred, err := buildWAFValidatedProxy("10.0.0.0/8", nil)
		require.NoError(t, err)
		require.NotNil(t, pred)
		assert.True(t, pred(reqFrom("10.1.2.3:5555", nil)))
		assert.False(t, pred(reqFrom("192.168.1.1:5555", nil)))
	})

	t.Run("cidr leg ignores forwarded headers", func(t *testing.T) {
		// The skip is a per-PEER judgement: only the immediate TCP peer counts.
		// A client-supplied X-Forwarded-For / X-Real-Ip naming an in-range IP
		// must never grant the skip, or the WAF becomes client-bypassable.
		pred, err := buildWAFValidatedProxy("10.0.0.0/8", nil)
		require.NoError(t, err)
		r := reqFrom("192.168.1.1:5555", nil)
		r.Header.Set("X-Forwarded-For", "10.1.2.3")
		r.Header.Set("X-Real-Ip", "10.1.2.3")
		assert.False(t, pred(r))
	})

	t.Run("edge-mtls and cidr combine as OR", func(t *testing.T) {
		pred, err := buildWAFValidatedProxy("edge-mtls, 10.0.0.0/8", func(cs *tls.ConnectionState) bool {
			return cs != nil
		})
		require.NoError(t, err)
		require.NotNil(t, pred)
		assert.True(t, pred(reqFrom("192.168.1.1:1", &tls.ConnectionState{})), "mtls leg")
		assert.True(t, pred(reqFrom("10.9.9.9:1", nil)), "cidr leg")
		assert.False(t, pred(reqFrom("192.168.1.1:1", nil)), "neither leg")
	})

	t.Run("invalid cidr fails fast", func(t *testing.T) {
		// Same fail-fast posture as TRUST_PROXY: a typo'd token must abort
		// startup (panic inside trustcidr/parapet), never silently never-match.
		assert.Panics(t, func() { _, _ = buildWAFValidatedProxy("edge-mtl", func(*tls.ConnectionState) bool { return true }) })
	})
}
