package cacherule_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/moonrhythm/parapet/pkg/waf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/moonrhythm/parapet-ingress-controller/cacherule"
)

func req(method, target string) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

// snap returns the shared-snapshot closure the edge passes into the hooks.
func snap(r *http.Request) func() waf.Input {
	return func() waf.Input { return waf.NewInput(r, "", "", 0) }
}

func idsOf(rs *cacherule.Ruleset) []string {
	var ids []string
	for _, o := range rs.Overrides() {
		ids = append(ids, o.ID)
	}
	return ids
}

func TestParse(t *testing.T) {
	t.Parallel()
	ovs, err := cacherule.Parse(
		"overrides:\n  - id: a\n    action: bypass\n",
		"",
		"overrides:\n  - id: b\n    ttl: 1h\n",
	)
	require.NoError(t, err)
	require.Len(t, ovs, 2)
	assert.Equal(t, "a", ovs[0].ID)
	assert.Equal(t, "b", ovs[1].ID)
}

func TestSetOverrides_RejectsAndKeepsLastGood(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ov   cacherule.Override
	}{
		{"empty id", cacherule.Override{ID: "", Action: "cache", TTL: "1h"}},
		{"id with colon", cacherule.Override{ID: "a:b", Action: "cache", TTL: "1h"}},
		{"id with slash", cacherule.Override{ID: "a/b", Action: "cache", TTL: "1h"}},
		{"bad action", cacherule.Override{ID: "x", Action: "nope"}},
		{"bad mode", cacherule.Override{ID: "x", Action: "cache", TTL: "1h", Mode: "audit"}},
		{"missing ttl", cacherule.Override{ID: "x", Action: "cache"}},
		{"ttl too small", cacherule.Override{ID: "x", Action: "cache", TTL: "100ms"}},
		{"bad ttl", cacherule.Override{ID: "x", Action: "cache", TTL: "abc"}},
		{"bad policy", cacherule.Override{ID: "x", Action: "cache", TTL: "1h", Policy: "nuke"}},
		{"bad status", cacherule.Override{ID: "x", Action: "cache", TTL: "1h", Status: []int{99}}},
		{"bypass with ttl", cacherule.Override{ID: "x", Action: "bypass", TTL: "1h"}},
		{"bypass with status", cacherule.Override{ID: "x", Action: "bypass", Status: []int{200}}},
		{"bypass with policy", cacherule.Override{ID: "x", Action: "bypass", Policy: "balanced"}},
		{"non-bool filter", cacherule.Override{ID: "x", Action: "cache", TTL: "1h", Filter: "request.method"}},
		{"bad filter syntax", cacherule.Override{ID: "x", Action: "cache", TTL: "1h", Filter: "request."}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rs := &cacherule.Ruleset{}
			require.NoError(t, rs.SetOverrides([]cacherule.Override{{ID: "keep", Action: "cache", TTL: "1h"}}))
			err := rs.SetOverrides([]cacherule.Override{c.ov})
			assert.Error(t, err)
			assert.Equal(t, []string{"keep"}, idsOf(rs), "last-good set must survive a rejected batch")
		})
	}
}

func TestSetOverrides_DuplicateID(t *testing.T) {
	t.Parallel()
	rs := &cacherule.Ruleset{}
	err := rs.SetOverrides([]cacherule.Override{
		{ID: "x", Action: "cache", TTL: "1h"},
		{ID: "x", Action: "bypass"},
	})
	assert.Error(t, err)
}

func TestBypass_FilterScopeAndNoFilter(t *testing.T) {
	t.Parallel()
	rs := &cacherule.Ruleset{}
	require.NoError(t, rs.SetOverrides([]cacherule.Override{
		{ID: "admin", Action: "bypass", Filter: `request.path.startsWith("/admin")`},
	}))
	r1 := req("GET", "/admin/x")
	assert.True(t, rs.MatchBypass(r1, snap(r1)), "filter matches ⇒ bypass")
	r2 := req("GET", "/public")
	assert.False(t, rs.MatchBypass(r2, snap(r2)), "filter excludes ⇒ no bypass")

	all := &cacherule.Ruleset{}
	require.NoError(t, all.SetOverrides([]cacherule.Override{{ID: "all", Action: "bypass"}}))
	r3 := req("GET", "/anything")
	assert.True(t, all.MatchBypass(r3, snap(r3)), "filterless bypass matches every request")
}

func TestBypass_FailsTowardNotCaching(t *testing.T) {
	t.Parallel()
	// Cost limit 1 makes every filter evaluation error. A bypass rule whose filter
	// errors must still bypass — caching is the dangerous action.
	rs := &cacherule.Ruleset{FilterCostLimit: 1}
	require.NoError(t, rs.SetOverrides([]cacherule.Override{
		{ID: "x", Action: "bypass", Filter: `request.method == "GET"`},
	}))
	r := req("GET", "/")
	assert.True(t, rs.MatchBypass(r, snap(r)), "filter error ⇒ bypass anyway")
}

func TestBypass_ShadowDoesNotBypass(t *testing.T) {
	t.Parallel()
	rs := &cacherule.Ruleset{}
	require.NoError(t, rs.SetOverrides([]cacherule.Override{
		{ID: "x", Action: "bypass", Mode: "shadow", Filter: `request.path == "/p"`},
	}))
	r := req("GET", "/p")
	assert.False(t, rs.MatchBypass(r, snap(r)), "shadow evaluates but never bypasses")
}

func TestForce_FirstMatchByPriority(t *testing.T) {
	t.Parallel()
	rs := &cacherule.Ruleset{}
	require.NoError(t, rs.SetOverrides([]cacherule.Override{
		{ID: "hi", Action: "cache", TTL: "1h", Priority: 200, Filter: `request.path.startsWith("/a")`},
		{ID: "lo", Action: "cache", TTL: "10m", Priority: 50, Filter: `request.path.startsWith("/a")`},
	}))
	r := req("GET", "/a/x")
	ov, ok := rs.Force(r, 200, snap(r))
	require.True(t, ok)
	assert.Equal(t, 10*time.Minute, ov.TTL, "lower priority number wins")
}

func TestForce_StatusGate(t *testing.T) {
	t.Parallel()
	rs := &cacherule.Ruleset{}
	require.NoError(t, rs.SetOverrides([]cacherule.Override{
		{ID: "s", Action: "cache", TTL: "1h", Status: []int{301, 404}},
	}))
	r := req("GET", "/x")
	_, ok := rs.Force(r, 200, snap(r))
	assert.False(t, ok, "200 not in the status list ⇒ no force")
	_, ok = rs.Force(r, 301, snap(r))
	assert.True(t, ok, "301 is in the status list ⇒ force")
}

func TestForce_FilterScope(t *testing.T) {
	t.Parallel()
	rs := &cacherule.Ruleset{}
	require.NoError(t, rs.SetOverrides([]cacherule.Override{
		{ID: "f", Action: "cache", TTL: "1h", Filter: `request.method == "GET"`},
	}))
	get := req("GET", "/x")
	_, ok := rs.Force(get, 200, snap(get))
	assert.True(t, ok)
	post := req("POST", "/x")
	_, ok = rs.Force(post, 200, snap(post))
	assert.False(t, ok)
}

func TestForce_FailSkipsOnError(t *testing.T) {
	t.Parallel()
	// An aggressive force whose filter errors must NOT apply — applying a force on
	// an error could cache shared/per-user content (the cross-user-leak risk).
	rs := &cacherule.Ruleset{FilterCostLimit: 1}
	require.NoError(t, rs.SetOverrides([]cacherule.Override{
		{ID: "agg", Action: "cache", TTL: "1h", Policy: "aggressive", Filter: `request.method == "GET"`},
	}))
	r := req("GET", "/x")
	_, ok := rs.Force(r, 200, snap(r))
	assert.False(t, ok, "filter error ⇒ honor the origin (skip the force)")
}

func TestForce_ShadowSkipsToNextRealRule(t *testing.T) {
	t.Parallel()
	rs := &cacherule.Ruleset{}
	require.NoError(t, rs.SetOverrides([]cacherule.Override{
		{ID: "sh", Action: "cache", TTL: "10m", Priority: 10, Mode: "shadow", Filter: `request.path == "/a"`},
		{ID: "real", Action: "cache", TTL: "1h", Priority: 20, Filter: `request.path == "/a"`},
	}))
	r := req("GET", "/a")
	ov, ok := rs.Force(r, 200, snap(r))
	require.True(t, ok)
	assert.Equal(t, time.Hour, ov.TTL, "shadow match is counted but skipped; the next real rule applies")
}

func TestForce_PolicyMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		policy string
		want   cache.OverrideMode
	}{
		{"", cache.OverrideBalanced},
		{"balanced", cache.OverrideBalanced},
		{"conservative", cache.OverrideConservative},
		{"aggressive", cache.OverrideAggressive},
	}
	for _, c := range cases {
		rs := &cacherule.Ruleset{}
		require.NoError(t, rs.SetOverrides([]cacherule.Override{
			{ID: "p", Action: "cache", TTL: "1h", Policy: c.policy},
		}))
		r := req("GET", "/x")
		ov, ok := rs.Force(r, 200, snap(r))
		require.True(t, ok)
		assert.Equal(t, c.want, ov.Mode, "policy %q", c.policy)
	}
}

func TestForce_StaleWindowsRideTheForce(t *testing.T) {
	t.Parallel()
	rs := &cacherule.Ruleset{}
	require.NoError(t, rs.SetOverrides([]cacherule.Override{
		{ID: "s", Action: "cache", TTL: "1h", StaleWhileRevalidate: "30s", StaleIfError: "5m"},
	}))
	r := req("GET", "/x")
	ov, ok := rs.Force(r, 200, snap(r))
	require.True(t, ok)
	assert.Equal(t, 30*time.Second, ov.StaleWhileRevalidate)
	assert.Equal(t, 5*time.Minute, ov.StaleIfError)
}

func TestObserve_CountsInScopeDecisions(t *testing.T) {
	t.Parallel()
	counts := map[string]int{}
	factory := func(name, action string) func(string) {
		return func(result string) { counts[name+"|"+action+"|"+result]++ }
	}
	rs := &cacherule.Ruleset{NamePrefix: "global", Observe: factory}
	require.NoError(t, rs.SetOverrides([]cacherule.Override{
		{ID: "b", Action: "bypass", Filter: `request.path == "/admin"`},
		{ID: "c", Action: "cache", TTL: "1h"},
	}))

	// In-scope bypass.
	radmin := req("GET", "/admin")
	assert.True(t, rs.MatchBypass(radmin, snap(radmin)))
	// Out-of-scope bypass: not counted.
	rother := req("GET", "/x")
	assert.False(t, rs.MatchBypass(rother, snap(rother)))
	// Force applies.
	_, ok := rs.Force(rother, 200, snap(rother))
	assert.True(t, ok)

	assert.Equal(t, 1, counts["global:b|bypass|applied"])
	assert.Equal(t, 1, counts["global:c|cache|applied"])
	assert.Equal(t, 0, counts["global:b|bypass|shadow"], "out-of-scope decisions are not counted")
}

func TestNeedsFilter(t *testing.T) {
	t.Parallel()
	none := &cacherule.Ruleset{}
	require.NoError(t, none.SetOverrides([]cacherule.Override{{ID: "x", Action: "cache", TTL: "1h"}}))
	assert.False(t, none.NeedsFilter())

	some := &cacherule.Ruleset{}
	require.NoError(t, some.SetOverrides([]cacherule.Override{{ID: "x", Action: "bypass", Filter: `request.method == "GET"`}}))
	assert.True(t, some.NeedsFilter())
}
