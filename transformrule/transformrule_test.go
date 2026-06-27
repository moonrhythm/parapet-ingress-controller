package transformrule_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/moonrhythm/parapet-ingress-controller/transformrule"
)

// goldenDoc is the EXACT cross-repo wire contract the deployer marshals from the
// api types with gopkg.in/yaml.v2 (SPEC §5.2). transformrule.Parse MUST consume
// it byte-for-byte.
const goldenDoc = `transforms:
- id: 42-9f3a1c
  description: force www
  phase: request
  filter: request.host == "acme.com"
  ops:
  - type: redirect
    to: https://www.acme.com$uri
    status: 308
  priority: 10
- id: 42-1a8d44
  description: security headers
  phase: response
  ops:
  - type: set-header
    name: Strict-Transport-Security
    value: max-age=63072000
  - type: remove-header
    name: Server
  mode: shadow
  priority: 0
- id: 42-cors01
  description: ""
  phase: response
  ops:
  - type: cors
    allow_origins:
    - https://app.acme.com
    allow_methods:
    - GET
    - POST
    allow_credentials: true
    max_age: 600s
  priority: 0
`

func serve(t *testing.T, z *transformrule.Zone, r *http.Request, downstream http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	if downstream == nil {
		downstream = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	}
	w := httptest.NewRecorder()
	z.ServeHandler(downstream).ServeHTTP(w, r)
	return w
}

func TestParse_Golden(t *testing.T) {
	t.Parallel()

	z, err := transformrule.Parse(transformrule.Options{}, goldenDoc)
	require.NoError(t, err, "the golden wire doc must parse exactly")
	require.NotNil(t, z)

	// request rules first, then response-interceptor rules, then cors rules.
	assert.Equal(t, []string{"42-9f3a1c", "42-1a8d44", "42-cors01"}, z.IDs())

	t.Run("redirect with $uri (request phase, sole-op short-circuit)", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://acme.com/pricing?ref=x", nil)
		var proxied bool
		w := serve(t, z, r, func(w http.ResponseWriter, _ *http.Request) { proxied = true })

		assert.False(t, proxied, "a matched redirect short-circuits before proxying")
		assert.Equal(t, http.StatusPermanentRedirect, w.Code) // 308
		assert.Equal(t, "https://www.acme.com/pricing?ref=x", w.Header().Get("Location"),
			"$uri expands to the original RequestURI")
	})

	t.Run("redirect filter scopes the match", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://www.acme.com/pricing", nil)
		var proxied bool
		w := serve(t, z, r, func(w http.ResponseWriter, _ *http.Request) {
			proxied = true
			w.Header().Set("Server", "origin/1.0")
			w.WriteHeader(http.StatusOK)
		})
		assert.True(t, proxied, "non-matching host proxies normally")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("shadow rule counts but mutates nothing", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://www.acme.com/", nil)
		w := serve(t, z, r, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "origin/1.0")
			w.WriteHeader(http.StatusOK)
		})
		assert.Empty(t, w.Header().Get("Strict-Transport-Security"), "shadow set-header applies nothing")
		assert.Equal(t, "origin/1.0", w.Header().Get("Server"), "shadow remove-header removes nothing")
	})

	t.Run("cors preflight short-circuit (dual-seam standalone mount)", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodOptions, "http://www.acme.com/", nil)
		r.Header.Set("Origin", "https://app.acme.com")
		var proxied bool
		w := serve(t, z, r, func(http.ResponseWriter, *http.Request) { proxied = true })

		assert.False(t, proxied, "cors answers the OPTIONS preflight without proxying")
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "https://app.acme.com", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
		assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "600", w.Header().Get("Access-Control-Max-Age"), "max_age 600s => 600")
	})

	t.Run("cors injects ACAO on a real request", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://www.acme.com/data", nil)
		r.Header.Set("Origin", "https://app.acme.com")
		w := serve(t, z, r, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		assert.Equal(t, "https://app.acme.com", w.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestParse_ResponseEnforce(t *testing.T) {
	t.Parallel()

	// enforce (no shadow): set-header + remove-header + set-status via the
	// ResponseInterceptor seam.
	z, err := transformrule.Parse(transformrule.Options{}, `
transforms:
- id: r1
  phase: response
  ops:
  - type: set-header
    name: Strict-Transport-Security
    value: max-age=63072000
  - type: remove-header
    name: Server
  - type: set-status
    status: 203
  priority: 0
`)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "http://x.test/", nil)
	w := serve(t, z, r, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "origin/1.0")
		w.WriteHeader(http.StatusOK) // upstream 200, overridden to 203
		_, _ = w.Write([]byte("body"))
	})

	assert.Equal(t, "max-age=63072000", w.Header().Get("Strict-Transport-Security"))
	assert.Empty(t, w.Header().Get("Server"), "remove-header drops it before commit")
	assert.Equal(t, 203, w.Code, "set-status overrides the upstream status (wroteHeader guard)")
}

func TestParse_RewritePathAndQuery(t *testing.T) {
	t.Parallel()

	// two request rules compose top-to-bottom; rule 25's predicate sees the path
	// already rewritten by rule 20 (SPEC §14.3).
	z, err := transformrule.Parse(transformrule.Options{}, `
transforms:
- id: rw-path
  phase: request
  filter: request.path.startsWith("/api/v1/")
  ops:
  - type: rewrite-path
    regex: ^/api/v1/(.*)$
    replace: /api/v2/$1
  priority: 20
- id: rw-query
  phase: request
  filter: request.path.startsWith("/api/")
  ops:
  - type: rewrite-query
    remove_query:
    - debug
  priority: 25
`)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "http://x.test/api/v1/users?debug=1&page=2", nil)
	var gotPath, gotQuery string
	serve(t, z, r, func(_ http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
	})

	assert.Equal(t, "/api/v2/users", gotPath, "regex rewrite-path applied")
	assert.Equal(t, "page=2", gotQuery, "rewrite-query saw the mutated path and dropped debug")
}

func TestParse_RewritePathLiteral(t *testing.T) {
	t.Parallel()

	z, err := transformrule.Parse(transformrule.Options{}, `
transforms:
- id: lit
  phase: request
  ops:
  - type: rewrite-path
    path: /healthz
  priority: 0
`)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "http://x.test/anything", nil)
	var gotPath string
	serve(t, z, r, func(_ http.ResponseWriter, r *http.Request) { gotPath = r.URL.Path })
	assert.Equal(t, "/healthz", gotPath)
}

func TestParse_PriorityOrder(t *testing.T) {
	t.Parallel()

	// two response rules set the same header; ascending priority means the
	// higher-priority rule runs LAST and wins.
	z, err := transformrule.Parse(transformrule.Options{}, `
transforms:
- id: late
  phase: response
  ops:
  - type: set-header
    name: X-Order
    value: high-prio
  priority: 20
- id: early
  phase: response
  ops:
  - type: set-header
    name: X-Order
    value: low-prio
  priority: 10
`)
	require.NoError(t, err)
	// IDs() reflects the sorted order: priority 10 (early) before priority 20 (late).
	assert.Equal(t, []string{"early", "late"}, z.IDs())

	r := httptest.NewRequest(http.MethodGet, "http://x.test/", nil)
	w := serve(t, z, r, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	assert.Equal(t, "high-prio", w.Header().Get("X-Order"), "higher priority runs last and wins")
}

func TestParse_BadFilterRejectsWholeDocument(t *testing.T) {
	t.Parallel()

	// A filter that fails to COMPILE rejects the WHOLE set all-or-nothing — the
	// good rule alongside it never takes effect (the controller keeps last-good).
	z, err := transformrule.Parse(transformrule.Options{}, `
transforms:
- id: good
  phase: response
  ops:
  - type: set-header
    name: X-Good
    value: "1"
  priority: 0
- id: bad
  phase: request
  filter: "request.host == "
  ops:
  - type: set-header
    name: X-Bad
    value: "1"
  priority: 0
`)
	require.Error(t, err, "an uncompilable filter rejects the whole document")
	assert.Nil(t, z)
}

func TestParse_EvalErrorSkipsOneRule(t *testing.T) {
	t.Parallel()

	// rule A's filter COMPILES but ERRORS at eval (int() of a non-numeric host);
	// it must be skipped (no mutation) while rule B still applies. A runtime eval
	// error never rejects the whole set — only a compile error does.
	z, err := transformrule.Parse(transformrule.Options{}, `
transforms:
- id: a-eval-error
  phase: request
  filter: int(request.host) > 0
  ops:
  - type: set-header
    name: X-A
    value: "1"
  priority: 10
- id: b-applies
  phase: request
  ops:
  - type: set-header
    name: X-B
    value: "1"
  priority: 20
`)
	require.NoError(t, err, "both filters compile; the error is at eval time")

	r := httptest.NewRequest(http.MethodGet, "http://acme.com/", nil)
	var gotA, gotB string
	serve(t, z, r, func(_ http.ResponseWriter, r *http.Request) {
		gotA = r.Header.Get("X-A")
		gotB = r.Header.Get("X-B")
	})
	assert.Empty(t, gotA, "the eval-error rule is skipped (no mutation)")
	assert.Equal(t, "1", gotB, "other rules still apply")
}

func TestParse_EmptyDocIsInert(t *testing.T) {
	t.Parallel()

	z, err := transformrule.Parse(transformrule.Options{}, "transforms:\n")
	require.NoError(t, err)
	require.NotNil(t, z)
	assert.True(t, z.Empty())

	r := httptest.NewRequest(http.MethodGet, "http://x.test/", nil)
	var proxied bool
	serve(t, z, r, func(http.ResponseWriter, *http.Request) { proxied = true })
	assert.True(t, proxied, "an empty zone is a pass-through")
}

func TestParse_CORSWildcardWithCredentialsRejected(t *testing.T) {
	t.Parallel()

	// Browsers forbid wildcard-with-credentials; cors.CORS.ServeHandler would
	// PANIC. Parse must reject it all-or-nothing instead of crashing the request
	// path.
	_, err := transformrule.Parse(transformrule.Options{}, `
transforms:
- id: bad-cors
  phase: response
  ops:
  - type: cors
    allow_origins:
    - "*"
    allow_credentials: true
  priority: 0
`)
	require.Error(t, err)
}

func TestParse_RedirectMustBeSoleOp(t *testing.T) {
	t.Parallel()

	_, err := transformrule.Parse(transformrule.Options{}, `
transforms:
- id: bad
  phase: request
  ops:
  - type: redirect
    to: https://x.test/
    status: 302
  - type: set-header
    name: X-Extra
    value: "1"
  priority: 0
`)
	require.Error(t, err, "redirect must be the only op in its rule")
}
