package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ipLimitDoc = `
limits:
  - id: ip-1
    key: ip
    rate: 1
    window: 1m
`

const hostLimitDoc = `
limits:
  - id: host-1
    key: host
    rate: 1
    window: 1m
`

// rlServe sends a request with the given Host + client IP through mw and
// reports the status code. The client IP rides X-Real-Ip — in production
// parapet's proxy layer (the outermost handler) sets it from the peer or a
// trusted X-Forwarded-For before any middleware runs.
func rlServe(mw http.Handler, host, ip string) int {
	req := httptest.NewRequest(http.MethodGet, "https://"+host+"/x", nil)
	req.Header.Set("X-Real-Ip", ip)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	return rec.Code
}

func TestEdgeRateLimit_GlobalEnforces(t *testing.T) {
	e := NewEdgeRateLimit(nil, nil)
	require.NoError(t, e.Update(1, []string{ipLimitDoc}, nil, nil, nil, `"e1"`))

	h := e.Global().ServeHandler(passed())
	assert.Equal(t, 200, rlServe(h, "acme.com", "10.1.1.1"), "first request within rate")
	assert.Equal(t, 429, rlServe(h, "acme.com", "10.1.1.1"), "second request over rate")
	assert.Equal(t, 200, rlServe(h, "acme.com", "10.1.1.2"), "another client has its own bucket")
}

func TestEdgeRateLimit_ZoneBoundByHost(t *testing.T) {
	e := NewEdgeRateLimit(nil, nil)
	require.NoError(t, e.Update(1, nil,
		map[string][]string{"cust1/basic": {ipLimitDoc}},
		map[string]string{"acme.com": "cust1/basic"},
		[]string{"acme.com"}, `"e1"`))

	h := e.Zone().ServeHandler(passed())
	assert.Equal(t, 200, rlServe(h, "acme.com", "10.2.2.2"))
	assert.Equal(t, 429, rlServe(h, "acme.com", "10.2.2.2"), "bound host enforces the zone limit")
	assert.Equal(t, 200, rlServe(h, "other.com", "10.2.2.2"), "unbound host passes (no zone)")
	assert.Equal(t, 200, rlServe(h, "other.com", "10.2.2.2"), "unbound host is never limited")
}

func TestEdgeRateLimit_KeepLastGoodAndCountersOnBadUpdate(t *testing.T) {
	e := NewEdgeRateLimit(nil, nil)
	require.NoError(t, e.Update(1, []string{ipLimitDoc}, nil, nil, nil, `"e1"`))

	h := e.Global().ServeHandler(passed())
	assert.Equal(t, 200, rlServe(h, "acme.com", "10.3.3.3"))

	// An invalid set (rate must be > 0) is rejected; the previous set — and its
	// live counters — stay in force, and the etag is NOT advanced so the bad
	// input is re-fetched and retried (re-warned) on the next poll instead of
	// 304ing forever.
	err := e.Update(2, []string{"limits:\n  - id: bad\n    key: ip\n    rate: -1\n    window: 1m\n"}, nil, nil, nil, `"e2"`)
	assert.Error(t, err)
	assert.Equal(t, `"e1"`, e.Etag(), "etag must not advance on a failed apply")
	assert.Equal(t, 429, rlServe(h, "acme.com", "10.3.3.3"), "last-good set still enforcing with its counters")
}

func TestEdgeRateLimit_CountersSurviveUnchangedUpdate(t *testing.T) {
	e := NewEdgeRateLimit(nil, nil)
	doc := "limits:\n  - id: ip-2\n    key: ip\n    rate: 2\n    window: 1m\n"
	require.NoError(t, e.Update(1, []string{doc}, nil, nil, nil, `"e1"`))

	h := e.Global().ServeHandler(passed())
	assert.Equal(t, 200, rlServe(h, "acme.com", "10.4.4.4"))

	// Re-applying an unchanged limit carries the strategy — and its counters —
	// over (SetLimits' cfgKey match), so the budget is NOT reset by a refresh.
	require.NoError(t, e.Update(2, []string{doc}, nil, nil, nil, `"e2"`))
	assert.Equal(t, 200, rlServe(h, "acme.com", "10.4.4.4"), "2/2 after carry-over")
	assert.Equal(t, 429, rlServe(h, "acme.com", "10.4.4.4"), "3rd request over the carried budget")
}

func TestEdgeRateLimit_KnownHostCollapse(t *testing.T) {
	e := NewEdgeRateLimit(nil, nil)
	require.NoError(t, e.Update(1, []string{hostLimitDoc}, nil, nil, []string{"a.com"}, `"e1"`))

	h := e.Global().ServeHandler(passed())
	// Hosts no Ingress declares collapse into ONE shared bucket: a random-Host
	// flood can't mint unbounded keys against a host-keyed limit.
	assert.Equal(t, 200, rlServe(h, "x.com", "10.5.5.5"))
	assert.Equal(t, 429, rlServe(h, "y.com", "10.5.5.5"), "undeclared hosts share the collapsed bucket")
	assert.Equal(t, 200, rlServe(h, "a.com", "10.5.5.5"), "declared host keeps its own bucket")
}

func TestEdgeRateLimit_EtagRoundtrips(t *testing.T) {
	e := NewEdgeRateLimit(nil, nil)
	assert.Equal(t, "", e.Etag())
	require.NoError(t, e.Update(3, nil, nil, nil, nil, `"e9"`))
	assert.Equal(t, `"e9"`, e.Etag())
}
