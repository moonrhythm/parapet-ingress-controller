package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, w.Update(1, globalRulesYAML, nil, nil, `"e1"`))

	h := w.Global().ServeHandler(passed())
	blocked := run(h, "GET", "https://acme.com/blocked")
	assert.Equal(t, 403, blocked.Code)
	assert.Contains(t, blocked.Body.String(), "blocked-by-global")

	ok := run(h, "GET", "https://acme.com/allowed")
	assert.Equal(t, 200, ok.Code)
	assert.Equal(t, "passed", ok.Body.String())
}

func TestEdgeWAF_ZoneBlocksWhenHostBound(t *testing.T) {
	w := NewEdgeWAF(nil, nil)
	require.NoError(t, w.Update(1, "",
		map[string]string{"ns/z": zoneRulesYAML},
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

func TestEdgeWAF_KeepLastGoodOnBadRuleset(t *testing.T) {
	w := NewEdgeWAF(nil, nil)
	require.NoError(t, w.Update(1, globalRulesYAML, nil, nil, `"e1"`))

	// A ruleset that fails to compile (non-bool expression) is rejected; the
	// previous good global ruleset stays live.
	err := w.Update(2, `rules:
  - id: bad
    expression: "1 + 1"
    action: block
`, nil, nil, `"e2"`)
	assert.Error(t, err)

	h := w.Global().ServeHandler(passed())
	blocked := run(h, "GET", "https://acme.com/blocked")
	assert.Equal(t, 403, blocked.Code, "previous good ruleset still blocks")
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
`, nil, nil, `"e1"`))

	h := w.Global().ServeHandler(passed())
	rec := run(h, "GET", "https://acme.com/anything")
	assert.Equal(t, 403, rec.Code)
	assert.Contains(t, rec.Body.String(), "blocked-by-geo")
}

func TestEdgeWAF_EtagRoundtrips(t *testing.T) {
	w := NewEdgeWAF(nil, nil)
	assert.Equal(t, "", w.Etag())
	require.NoError(t, w.Update(3, globalRulesYAML, nil, nil, `"e9"`))
	assert.Equal(t, `"e9"`, w.Etag())
}

func TestEdgeWAF_ZoneRemovedOnNextUpdateButKeptOnBadEdit(t *testing.T) {
	w := NewEdgeWAF(nil, nil)
	require.NoError(t, w.Update(1, "",
		map[string]string{"ns/z": zoneRulesYAML},
		map[string]string{"acme.com": "ns/z"}, `"e1"`))

	// A bad edit to the zone keeps its last-good rules.
	_ = w.Update(2, "",
		map[string]string{"ns/z": "rules:\n  - id: bad\n    expression: \"1+1\"\n    action: block\n"},
		map[string]string{"acme.com": "ns/z"}, `"e2"`)
	h := w.Zone().ServeHandler(passed())
	assert.Equal(t, 403, run(h, "GET", "https://acme.com/zoneblocked").Code, "bad zone edit keeps last-good")

	// A zone absent from the next payload is dropped.
	require.NoError(t, w.Update(3, "", nil, nil, `"e3"`))
	h2 := w.Zone().ServeHandler(passed())
	assert.Equal(t, 200, run(h2, "GET", "https://acme.com/zoneblocked").Code, "dropped zone no longer evaluated")
}
