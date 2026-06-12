package ratelimitrule_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/moonrhythm/parapet-ingress-controller/ratelimitrule"
)

// filtered is a limit() with a CEL filter attached.
func filtered(id string, rate int, window, filter string) ratelimitrule.Limit {
	l := limit(id, rate, window)
	l.Filter = filter
	return l
}

func TestFilter_GatesScope(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	// Limit only POSTs, rate 1/min: the 2nd POST is rejected, but GETs are out of
	// scope and never limited (nor counted).
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{
		filtered("post-only", 1, "1m", `request.method == "POST"`),
	}))

	_, called := serve(l, http.MethodPost, "/", nil)
	assert.True(t, called, "1st POST admitted")
	w, called := serve(l, http.MethodPost, "/", nil)
	assert.False(t, called, "2nd POST limited")
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// GETs are excluded by the filter — unlimited regardless of how many.
	for i := 0; i < 5; i++ {
		w, called := serve(l, http.MethodGet, "/", nil)
		assert.True(t, called, "GET out of filter scope: always admitted")
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func TestFilter_PathAndHeader(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{
		filtered("api-anon", 1, "1m",
			`request.path.startsWith("/api/") && !("authorization" in request.headers)`),
	}))

	// /api/ without auth: in scope.
	_, _ = serve(l, http.MethodGet, "/api/x", nil)
	w, called := serve(l, http.MethodGet, "/api/x", nil)
	assert.False(t, called)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// /api/ WITH auth: out of scope, never limited.
	for i := 0; i < 3; i++ {
		_, called := serve(l, http.MethodGet, "/api/x", map[string]string{"Authorization": "Bearer t"})
		assert.True(t, called)
	}
	// non-/api path: out of scope.
	for i := 0; i < 3; i++ {
		_, called := serve(l, http.MethodGet, "/web", nil)
		assert.True(t, called)
	}
}

func TestFilter_InvalidExpressionRejected(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}

	// Non-bool result.
	err := l.SetLimits([]ratelimitrule.Limit{filtered("x", 1, "1m", `request.method`)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "filter")

	// Syntax error.
	err = l.SetLimits([]ratelimitrule.Limit{filtered("x", 1, "1m", `request.method ==`)})
	require.Error(t, err)

	// Unknown variable.
	err = l.SetLimits([]ratelimitrule.Limit{filtered("x", 1, "1m", `nope == "y"`)})
	require.Error(t, err)
}

func TestFilter_RejectionIsAllOrNothing(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	// Establish a good set.
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{limit("good", 1, "1m")}))
	require.Equal(t, []string{"good"}, l.IDs())

	// A batch with a bad filter is rejected wholesale; the last-good set stays.
	err := l.SetLimits([]ratelimitrule.Limit{
		limit("good", 1, "1m"),
		filtered("bad", 1, "1m", `request.method`),
	})
	require.Error(t, err)
	assert.Equal(t, []string{"good"}, l.IDs(), "previous set kept after rejected batch")
}

func TestFilter_FailsOpenOnEvalError(t *testing.T) {
	t.Parallel()

	// A cost limit of 1 makes every filter evaluation exceed budget and error.
	l := &ratelimitrule.Limiter{FilterCostLimit: 1}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{
		filtered("post", 1, "1m", `request.method == "POST"`),
	}))

	// Every eval errors ⇒ fail open ⇒ the limit is skipped ⇒ nothing is ever
	// limited, even well past the rate.
	for i := 0; i < 4; i++ {
		w, called := serve(l, http.MethodPost, "/", nil)
		assert.True(t, called, "fail-open: request admitted despite filter error")
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func TestFilter_CountersPreservedAcrossFilterOnlyEdit(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{
		filtered("x", 2, "1m", `request.method == "POST"`),
	}))

	// Consume the budget of 2.
	_, c1 := serve(l, http.MethodPost, "/", nil)
	_, c2 := serve(l, http.MethodPost, "/", nil)
	require.True(t, c1 && c2)

	// Edit only the filter (key/algorithm/rate/window unchanged ⇒ cfgKey same ⇒
	// strategy carried over). The live counter must survive.
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{
		filtered("x", 2, "1m", `request.method == "POST" || request.method == "PUT"`),
	}))

	w, called := serve(l, http.MethodPost, "/", nil)
	assert.False(t, called, "counter preserved: 3rd POST still limited after filter-only edit")
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestFilter_SharedSnapshotAcrossLimits(t *testing.T) {
	t.Parallel()

	d := newDecisions()
	l := &ratelimitrule.Limiter{NamePrefix: "t", Observe: d.factory}
	// Two filtered limits, both matching the same POST request: both must
	// evaluate against the one shared snapshot and both count.
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{
		filtered("a", 100, "1m", `request.method == "POST"`),
		filtered("b", 100, "1m", `request.path == "/api"`),
	}))

	_, called := serve(l, http.MethodPost, "/api", nil)
	require.True(t, called)
	assert.Equal(t, 1, d.allowed["t:a"])
	assert.Equal(t, 1, d.allowed["t:b"])

	// A request matching only one filter counts only for that limit.
	_, called = serve(l, http.MethodGet, "/api", nil)
	require.True(t, called)
	assert.Equal(t, 1, d.allowed["t:a"], "limit a (POST) not counted for a GET")
	assert.Equal(t, 2, d.allowed["t:b"], "limit b (/api) counted again")
}

func TestFilter_GeoReferenceWithoutResolverNeverMatches(t *testing.T) {
	t.Parallel()

	// No Country/ASN resolver wired. A geo KEY would be rejected at load, but a
	// geo FILTER is accepted — request.country is just "" and never matches, so
	// the limit is effectively inert rather than a load error.
	l := &ratelimitrule.Limiter{}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{
		filtered("th-only", 1, "1m", `request.country == "TH"`),
	}))

	for i := 0; i < 4; i++ {
		w, called := serve(l, http.MethodGet, "/", nil)
		assert.True(t, called, "country filter without DB never matches ⇒ limit inert")
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func TestFilter_AppliesWhenResolverPresent(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{
		Country: func(*http.Request) string { return "TH" },
	}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{
		filtered("th-only", 1, "1m", `request.country == "TH"`),
	}))

	_, called := serve(l, http.MethodGet, "/", nil)
	assert.True(t, called, "1st TH request admitted")
	w, called := serve(l, http.MethodGet, "/", nil)
	assert.False(t, called, "2nd TH request limited (filter matched)")
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}
