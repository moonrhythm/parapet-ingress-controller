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
	transformInline := idx("ctrl.Use(plugin.Transform(")
	upstreamProto := idx("ctrl.Use(plugin.UpstreamProtocol)")
	upstreamHost := idx("ctrl.Use(plugin.UpstreamHost)")
	upstreamPath := idx("ctrl.Use(plugin.UpstreamPath)")
	basicAuth := idx("ctrl.Use(plugin.BasicAuth)")
	forwardAuth := idx("ctrl.Use(plugin.ForwardAuth)")
	stripPrefix := idx("ctrl.Use(plugin.StripPrefix)")

	// after WAF + ratelimit
	require.Less(t, waf, transform, "transform must register AFTER WAFZone")
	require.Less(t, rateLimit, transform, "transform must register AFTER RateLimit")

	// the inline set runs after the zone (shared config first, the ingress's own
	// rules see and can override its effects) and shares the whole F1 slot.
	require.Less(t, transform, transformInline, "inline transform must register AFTER TransformZone")

	// before the upstream rewrites + auth + strip-prefix
	for name, pos := range map[string]int{"zone": transform, "inline": transformInline} {
		require.Less(t, pos, upstreamProto, "%s transform must register BEFORE UpstreamProtocol", name)
		require.Less(t, pos, upstreamHost, "%s transform must register BEFORE UpstreamHost", name)
		require.Less(t, pos, upstreamPath, "%s transform must register BEFORE UpstreamPath", name)
		require.Less(t, pos, basicAuth, "%s transform must register BEFORE BasicAuth", name)
		require.Less(t, pos, forwardAuth,
			"%s transform must register BEFORE ForwardAuth so X-Auth-* re-stamp overwrites any forged identity header (SPEC §4.4)", name)
		require.Less(t, pos, stripPrefix, "%s transform must register BEFORE StripPrefix", name)
	}
}
