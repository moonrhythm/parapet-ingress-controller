package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const corazaGlobalRule = `
SecRuleEngine On
SecRule REQUEST_URI "@contains /attack" "id:9001,phase:1,deny,status:403"
`

const corazaZoneRule = `
SecRuleEngine On
SecRule REQUEST_URI "@contains /admin" "id:9002,phase:1,deny,status:403"
`

func corazaPassed() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestEdgeCoraza_GlobalBlocks(t *testing.T) {
	c := NewEdgeCoraza(nil, 0)
	require.NoError(t, c.Update(1, corazaGlobalRule, nil, nil, `"e1"`))

	h := c.Global().ServeHandler(corazaPassed())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://app/attack", nil))
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://app/safe", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEdgeCoraza_ZonePathAware(t *testing.T) {
	c := NewEdgeCoraza(nil, 0)
	require.NoError(t, c.Update(1, "",
		map[string]string{"cust1/z": corazaZoneRule},
		map[string]string{"acme.com/admin": "cust1/z", "acme.com/admin/": "cust1/z"},
		`"e1"`))

	h := c.Zone().ServeHandler(corazaPassed())

	// bound route -> zone enforces
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://acme.com/admin/users", nil))
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// unbound host -> passes through
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://other.com/admin", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEdgeCoraza_KeepLastGoodOnBadRuleset(t *testing.T) {
	c := NewEdgeCoraza(nil, 0)
	require.NoError(t, c.Update(1, corazaGlobalRule, nil, nil, `"e1"`))

	// a broken global ruleset must be rejected, keeping last-good
	err := c.Update(2, "SecRule not valid )(", nil, nil, `"e2"`)
	require.Error(t, err)

	h := c.Global().ServeHandler(corazaPassed())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://app/attack", nil))
	assert.Equal(t, http.StatusForbidden, rec.Code, "last-good ruleset stays live")
	assert.Equal(t, `"e1"`, c.Etag(), "etag not advanced on a rejected apply")
}

func TestEdgeCoraza_PassThroughUntilLoaded(t *testing.T) {
	c := NewEdgeCoraza(nil, 0)
	h := c.Global().ServeHandler(corazaPassed())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://app/attack", nil))
	assert.Equal(t, http.StatusOK, rec.Code, "no rules loaded -> pass-through")
}
