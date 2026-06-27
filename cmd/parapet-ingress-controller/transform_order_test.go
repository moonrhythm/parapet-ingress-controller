package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTransformZoneRegistrationSlot is the security-critical F1 guard (SPEC
// §4.4): the TransformZone plugin MUST be registered in ctrl.plugins AFTER WAF
// and RateLimit (so security and throttle see the original, un-rewritten
// request) and BEFORE UpstreamProtocol/Host/Path, BasicAuth, ForwardAuth and
// StripPrefix (so ForwardAuth's delete + re-stamp of the X-Auth-* identity
// headers always overwrites any transform-forged identity header).
//
// Registration order == request-processing order (first ctrl.Use = outermost),
// so the order of the ctrl.Use(plugin.X) lines in main.go IS the onion. This
// test pins that source order; moving the TransformZone registration out of its
// slot fails here loudly.
func TestTransformZoneRegistrationSlot(t *testing.T) {
	t.Parallel()

	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	src, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "main.go"))
	require.NoError(t, err)
	body := string(src)

	idx := func(needle string) int {
		i := strings.Index(body, needle)
		require.GreaterOrEqualf(t, i, 0, "registration not found in main.go: %s", needle)
		return i
	}

	waf := idx("ctrl.Use(plugin.WAFZone(")
	rateLimit := idx("ctrl.Use(plugin.RateLimit)")
	transform := idx("ctrl.Use(plugin.TransformZone(")
	upstreamProto := idx("ctrl.Use(plugin.UpstreamProtocol)")
	upstreamHost := idx("ctrl.Use(plugin.UpstreamHost)")
	upstreamPath := idx("ctrl.Use(plugin.UpstreamPath)")
	basicAuth := idx("ctrl.Use(plugin.BasicAuth)")
	forwardAuth := idx("ctrl.Use(plugin.ForwardAuth)")
	stripPrefix := idx("ctrl.Use(plugin.StripPrefix)")

	// after WAF + ratelimit
	require.Less(t, waf, transform, "transform must register AFTER WAFZone")
	require.Less(t, rateLimit, transform, "transform must register AFTER RateLimit")

	// before the upstream rewrites + auth + strip-prefix
	require.Less(t, transform, upstreamProto, "transform must register BEFORE UpstreamProtocol")
	require.Less(t, transform, upstreamHost, "transform must register BEFORE UpstreamHost")
	require.Less(t, transform, upstreamPath, "transform must register BEFORE UpstreamPath")
	require.Less(t, transform, basicAuth, "transform must register BEFORE BasicAuth")
	require.Less(t, transform, forwardAuth,
		"transform must register BEFORE ForwardAuth so X-Auth-* re-stamp overwrites any forged identity header (SPEC §4.4)")
	require.Less(t, transform, stripPrefix, "transform must register BEFORE StripPrefix")
}
