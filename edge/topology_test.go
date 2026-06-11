package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func topoReq(host, path string) *http.Request {
	return httptest.NewRequest(http.MethodGet, "https://"+host+path, nil)
}

func TestEdgeTopology_Empty(t *testing.T) {
	tp := NewEdgeTopology()
	_, ok := tp.resolveWAFZone(topoReq("acme.com", "/x"))
	assert.False(t, ok)
	_, ok = tp.resolveRLZone(topoReq("acme.com", "/x"))
	assert.False(t, ok)
	assert.False(t, tp.IsKnownHost("acme.com"))
	assert.Equal(t, "", tp.Etag())
	assert.EqualValues(t, 0, tp.Generation())
}

// The WAF matcher, the rate-limit matcher, and the known-host set are independent:
// a request resolves to its WAF zone and its (possibly different) rate-limit zone
// from the one fetched topology.
func TestEdgeTopology_UpdateResolvesIndependently(t *testing.T) {
	tp := NewEdgeTopology()
	tp.Update(5,
		map[string]string{"acme.com/api": "ns/waf", "acme.com/api/": "ns/waf"}, nil, // waf route map
		map[string]string{"acme.com/": "ns/rl"}, nil, // rl route map (whole-host subtree)
		[]string{"acme.com"}, `"t1"`)

	k, ok := tp.resolveWAFZone(topoReq("acme.com", "/api/x"))
	assert.True(t, ok)
	assert.Equal(t, "ns/waf", k)
	k, ok = tp.resolveRLZone(topoReq("acme.com", "/api/x"))
	assert.True(t, ok)
	assert.Equal(t, "ns/rl", k)

	// /web has no WAF binding, but the rate-limit "/" subtree covers it.
	_, ok = tp.resolveWAFZone(topoReq("acme.com", "/web"))
	assert.False(t, ok, "no waf route for /web")
	_, ok = tp.resolveRLZone(topoReq("acme.com", "/web"))
	assert.True(t, ok, "rl subtree / covers /web")

	assert.True(t, tp.IsKnownHost("acme.com"))
	assert.False(t, tp.IsKnownHost("evil.com"))
	assert.Equal(t, `"t1"`, tp.Etag())
	assert.EqualValues(t, 5, tp.Generation())
}

// route maps absent (an older CP would only have sent host maps) → synthesized
// into whole-host "host/" subtree patterns, same as the WAF/RL matchers did.
func TestEdgeTopology_LegacyHostZoneFallback(t *testing.T) {
	tp := NewEdgeTopology()
	tp.Update(1, nil, map[string]string{"acme.com": "ns/waf"},
		nil, map[string]string{"acme.com": "ns/rl"}, []string{"acme.com"}, `"t1"`)

	k, ok := tp.resolveWAFZone(topoReq("acme.com", "/anything"))
	assert.True(t, ok)
	assert.Equal(t, "ns/waf", k)
	k, ok = tp.resolveRLZone(topoReq("acme.com", "/anything"))
	assert.True(t, ok)
	assert.Equal(t, "ns/rl", k)
}
