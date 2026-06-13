package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getReq(target string) *http.Request {
	return httptest.NewRequest(http.MethodGet, target, nil)
}

const cacheGlobalBypassAdmin = `overrides:
  - id: g-admin
    action: bypass
    filter: request.path.startsWith("/admin")
`

const cacheGlobalForceShared = `overrides:
  - id: g-shared
    action: cache
    ttl: 10m
    filter: request.path.startsWith("/shared")
`

const cacheZoneForceAPI = `overrides:
  - id: z-api
    action: cache
    ttl: 1h
    filter: request.path.startsWith("/api")
  - id: z-shared
    action: cache
    ttl: 1h
    filter: request.path.startsWith("/shared")
  - id: z-private
    action: bypass
    filter: request.path.startsWith("/private")
`

func TestEdgeCacheOverride_GlobalBypassAndZoneForce(t *testing.T) {
	t.Parallel()
	e := NewEdgeCacheOverride(nil, nil)
	require.NoError(t, e.Update(1,
		[]string{cacheGlobalBypassAdmin},
		map[string][]string{"cust/z": {cacheZoneForceAPI}},
		map[string]string{"t1.example.com/api/": "cust/z", "t1.example.com/private/": "cust/z"},
		"v1",
	))

	// Global bypass: /admin anywhere is never cached.
	assert.False(t, e.Cacheable(getReq("http://anything.example.com/admin/x")))
	assert.True(t, e.Cacheable(getReq("http://anything.example.com/other")))

	// Zone force: a request routed into the zone gets its TTL.
	ov := e.Override(getReq("http://t1.example.com/api/widgets"), 200, nil)
	require.NotNil(t, ov)
	assert.Equal(t, time.Hour, ov.TTL)

	// A request that resolves to no zone has no force (and no global force here).
	assert.Nil(t, e.Override(getReq("http://t1.example.com/elsewhere"), 200, nil))
	assert.Nil(t, e.Override(getReq("http://other.example.com/api/widgets"), 200, nil))
}

func TestEdgeCacheOverride_BypassUnion(t *testing.T) {
	t.Parallel()
	e := NewEdgeCacheOverride(nil, nil)
	require.NoError(t, e.Update(1,
		nil, // no global rules
		map[string][]string{"cust/z": {cacheZoneForceAPI}},
		map[string]string{"t1.example.com/private/": "cust/z"},
		"v1",
	))
	// Zone bypass fires even with no global bypass (union).
	assert.False(t, e.Cacheable(getReq("http://t1.example.com/private/data")))
	assert.True(t, e.Cacheable(getReq("http://t1.example.com/private-ish")))
}

func TestEdgeCacheOverride_GlobalForceBeatsZone(t *testing.T) {
	t.Parallel()
	e := NewEdgeCacheOverride(nil, nil)
	require.NoError(t, e.Update(1,
		[]string{cacheGlobalForceShared},                   // global forces /shared to 10m
		map[string][]string{"cust/z": {cacheZoneForceAPI}}, // zone would force /shared to 1h
		map[string]string{"t1.example.com/shared/": "cust/z"},
		"v1",
	))
	ov := e.Override(getReq("http://t1.example.com/shared/x"), 200, nil)
	require.NotNil(t, ov)
	assert.Equal(t, 10*time.Minute, ov.TTL, "global force is authoritative over the zone")
}

func TestEdgeCacheOverride_FailStaticEtagWithheld(t *testing.T) {
	t.Parallel()
	e := NewEdgeCacheOverride(nil, nil)
	require.NoError(t, e.Update(1, []string{cacheGlobalBypassAdmin}, nil, nil, "v1"))
	assert.Equal(t, "v1", e.Etag())

	// A global set that fails to compile (cache action without ttl) is rejected;
	// the etag must NOT advance so the next poll re-fetches and re-warns.
	badDoc := "overrides:\n  - id: x\n    action: cache\n"
	err := e.Update(2, []string{badDoc}, nil, nil, "v2")
	require.Error(t, err)
	assert.Equal(t, "v1", e.Etag(), "etag withheld on a rejected apply")

	// Recovery: a clean apply advances the etag again.
	require.NoError(t, e.Update(3, []string{cacheGlobalBypassAdmin}, nil, nil, "v3"))
	assert.Equal(t, "v3", e.Etag())
}

func TestEdgeCacheOverride_EmptyIsHonorOrigin(t *testing.T) {
	t.Parallel()
	e := NewEdgeCacheOverride(nil, nil)
	// No payload applied: every request is cacheable and nothing is forced.
	assert.True(t, e.Cacheable(getReq("http://x.example.com/admin")))
	assert.Nil(t, e.Override(getReq("http://x.example.com/api"), 200, nil))
}
