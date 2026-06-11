package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/moonrhythm/parapet-ingress-controller/wafclaim"
)

const globalRulesYAML = `
rules:
  - id: block-path
    expression: request.path == "/blocked"
    action: block
    status: 403
    message: blocked-by-global
`

const zoneRulesYAML = `
rules:
  - id: zone-block
    expression: request.path == "/zoneblocked"
    action: block
    status: 403
    message: blocked-by-zone
`

// run sends a request through mw -> a "passed" sentinel handler, returning the
// recorder.
func run(mw http.Handler, method, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	return rec
}

func passed() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("passed"))
	})
}

func TestEdgeWAF_GlobalBlocksMatchingPath(t *testing.T) {
	w := NewEdgeWAF(nil, nil)
	require.NoError(t, w.Update(1, globalRulesYAML, nil, nil, nil, `"e1"`))

	h := w.Global().ServeHandler(passed())
	blocked := run(h, "GET", "https://acme.com/blocked")
	assert.Equal(t, 403, blocked.Code)
	assert.Contains(t, blocked.Body.String(), "blocked-by-global")

	ok := run(h, "GET", "https://acme.com/allowed")
	assert.Equal(t, 200, ok.Code)
	assert.Equal(t, "passed", ok.Body.String())
}

func TestEdgeWAF_ZoneBlocksWhenHostBound(t *testing.T) {
	// Legacy host-level binding (route_zone_map absent — an older CP): the host
	// map is synthesized into whole-host subtree patterns.
	w := NewEdgeWAF(nil, nil)
	require.NoError(t, w.Update(1, "",
		map[string]string{"ns/z": zoneRulesYAML},
		nil,
		map[string]string{"acme.com": "ns/z"},
		`"e1"`))

	h := w.Zone().ServeHandler(passed())

	// Bound host -> zone rule fires.
	blocked := run(h, "GET", "https://acme.com/zoneblocked")
	assert.Equal(t, 403, blocked.Code)
	assert.Contains(t, blocked.Body.String(), "blocked-by-zone")

	// Same path on an unbound host -> passes (no zone).
	other := run(h, "GET", "https://other.com/zoneblocked")
	assert.Equal(t, 200, other.Code)

	// Bound host, non-matching path -> passes.
	ok := run(h, "GET", "https://acme.com/fine")
	assert.Equal(t, 200, ok.Code)
}

const blockAllZoneYAML = `
rules:
  - id: zone2-block-all
    expression: "true"
    action: block
    status: 403
    message: blocked-by-zone2
`

func TestEdgeWAF_ZonePathAware(t *testing.T) {
	// Two ingresses share a host: /api (Prefix) is bound to zone z2 (which
	// blocks everything it evaluates), /web (Prefix) to z1 (which only blocks
	// request.path == "/zoneblocked"). Route patterns are the controller's
	// route keys, so the edge resolves each path to its own zone — the case
	// host-level binding could not represent.
	w := NewEdgeWAF(nil, nil)
	require.NoError(t, w.Update(1, "",
		map[string]string{"ns/z1": zoneRulesYAML, "ns/z2": blockAllZoneYAML},
		map[string]string{
			"acme.com/api":  "ns/z2",
			"acme.com/api/": "ns/z2",
			"acme.com/web":  "ns/z1",
			"acme.com/web/": "ns/z1",
		},
		nil, `"e1"`))

	h := w.Zone().ServeHandler(passed())

	// /api subtree resolves to z2: blocked.
	blocked := run(h, "GET", "https://acme.com/api/users")
	assert.Equal(t, 403, blocked.Code)
	assert.Contains(t, blocked.Body.String(), "blocked-by-zone2")

	// /web subtree resolves to z1, NOT z2 — the block-all zone must not leak
	// onto its host neighbor's path.
	assert.Equal(t, 200, run(h, "GET", "https://acme.com/web/users").Code, "z2 must not leak into z1's path")

	// A path bound to neither route has no zone at all.
	assert.Equal(t, 200, run(h, "GET", "https://acme.com/zoneblocked").Code, "unbound path has no zone (z1's rule would have fired)")

	// An unbound host never resolves a zone.
	assert.Equal(t, 200, run(h, "GET", "https://other.com/api/x").Code)
}

func TestEdgeWAF_RouteZonePreferredOverHostZone(t *testing.T) {
	// When the CP ships route_zone_map, the legacy host map is ignored — the
	// edge must not blend the two models.
	w := NewEdgeWAF(nil, nil)
	require.NoError(t, w.Update(1, "",
		map[string]string{"ns/z": zoneRulesYAML},
		map[string]string{"acme.com/api/": "ns/z"},
		map[string]string{"acme.com": "ns/z"},
		`"e1"`))

	h := w.Zone().ServeHandler(passed())
	assert.Equal(t, 200, run(h, "GET", "https://acme.com/zoneblocked").Code, "host-level binding ignored when route map present")
}

func TestEdgeWAF_KeepLastGoodOnBadRuleset(t *testing.T) {
	w := NewEdgeWAF(nil, nil)
	require.NoError(t, w.Update(1, globalRulesYAML, nil, nil, nil, `"e1"`))

	// A ruleset that fails to compile (non-bool expression) is rejected; the
	// previous good global ruleset stays live, and the etag + generation are
	// NOT advanced — the old etag means the bad input is re-fetched and retried
	// on the next poll instead of 304ing forever, and the claim keeps carrying
	// the last cleanly-applied generation.
	err := w.Update(2, `rules:
  - id: bad
    expression: "1 + 1"
    action: block
`, nil, nil, nil, `"e2"`)
	assert.Error(t, err)
	assert.Equal(t, `"e1"`, w.Etag(), "etag must not advance on a failed apply")

	h := w.Global().ServeHandler(passed())
	blocked := run(h, "GET", "https://acme.com/blocked")
	assert.Equal(t, 403, blocked.Code, "previous good ruleset still blocks")
}

func TestEdgeWAF_BadFirstSnapshotNeverClaims(t *testing.T) {
	// An edge whose FIRST snapshot fails to compile keeps the empty boot
	// ruleset — it must not claim WAF validation, or a WAF_VALIDATED_PROXY
	// core would skip its own WAF for traffic that was screened by nothing.
	w := NewEdgeWAF(nil, nil)
	err := w.Update(1, `rules:
  - id: bad
    expression: "1 + 1"
    action: block
`, nil, nil, nil, `"e1"`)
	assert.Error(t, err)

	var got string
	h := w.ClaimStamp().ServeHandler(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(wafclaim.Header)
		rw.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "https://acme.com/x", nil)
	req.Header.Set(wafclaim.Header, "spoofed")
	h.ServeHTTP(httptest.NewRecorder(), req)
	assert.Empty(t, got, "no claim on the empty boot ruleset — and the inbound value is deleted even at generation 0")
	assert.Equal(t, "", w.Etag(), "failed first apply keeps no etag, so the snapshot is retried")
}

func TestEdgeWAF_CountryResolverWired(t *testing.T) {
	country := func(_ *http.Request) string { return "XX" }
	w := NewEdgeWAF(country, nil)
	require.NoError(t, w.Update(1, `rules:
  - id: geo
    expression: request.country == "XX"
    action: block
    status: 403
    message: blocked-by-geo
`, nil, nil, nil, `"e1"`))

	h := w.Global().ServeHandler(passed())
	rec := run(h, "GET", "https://acme.com/anything")
	assert.Equal(t, 403, rec.Code)
	assert.Contains(t, rec.Body.String(), "blocked-by-geo")
}

func TestEdgeWAF_EtagRoundtrips(t *testing.T) {
	w := NewEdgeWAF(nil, nil)
	assert.Equal(t, "", w.Etag())
	require.NoError(t, w.Update(3, globalRulesYAML, nil, nil, nil, `"e9"`))
	assert.Equal(t, `"e9"`, w.Etag())
}

func TestEdgeWAF_ClaimStamp(t *testing.T) {
	w := NewEdgeWAF(nil, nil)

	var got string
	sentinel := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(wafclaim.Header)
		rw.WriteHeader(http.StatusOK)
	})
	h := w.ClaimStamp().ServeHandler(sentinel)

	// Before the first CP snapshot (generation 0) nothing is stamped — the
	// empty boot ruleset must not claim validation, so the core's
	// WAF_VALIDATED_PROXY keeps evaluating this edge's traffic.
	run(h, "GET", "https://acme.com/x")
	assert.Empty(t, got)

	// Once a snapshot lands, the claim is the generation — Set overwrites any
	// inbound value even without StripWAFClaim upstream.
	require.NoError(t, w.Update(7, globalRulesYAML, nil, nil, nil, `"e1"`))
	req := httptest.NewRequest(http.MethodGet, "https://acme.com/x", nil)
	req.Header.Set(wafclaim.Header, "spoofed")
	h.ServeHTTP(httptest.NewRecorder(), req)
	assert.Equal(t, "7", got)
}

func TestStripWAFClaim(t *testing.T) {
	var got string
	h := StripWAFClaim().ServeHandler(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(wafclaim.Header)
		rw.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "https://acme.com/x", nil)
	req.Header.Set(wafclaim.Header, "1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	assert.Empty(t, got, "client-supplied claim must never pass the edge")
}

func TestEdgeWAF_ZoneRemovedOnNextUpdateButKeptOnBadEdit(t *testing.T) {
	w := NewEdgeWAF(nil, nil)
	require.NoError(t, w.Update(1, "",
		map[string]string{"ns/z": zoneRulesYAML},
		map[string]string{"acme.com/": "ns/z"}, nil, `"e1"`))

	// A bad edit to the zone keeps its last-good rules.
	_ = w.Update(2, "",
		map[string]string{"ns/z": "rules:\n  - id: bad\n    expression: \"1+1\"\n    action: block\n"},
		map[string]string{"acme.com/": "ns/z"}, nil, `"e2"`)
	h := w.Zone().ServeHandler(passed())
	assert.Equal(t, 403, run(h, "GET", "https://acme.com/zoneblocked").Code, "bad zone edit keeps last-good")

	// A zone absent from the next payload is dropped.
	require.NoError(t, w.Update(3, "", nil, nil, nil, `"e3"`))
	h2 := w.Zone().ServeHandler(passed())
	assert.Equal(t, 200, run(h2, "GET", "https://acme.com/zoneblocked").Code, "dropped zone no longer evaluated")
}
