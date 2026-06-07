package edgecp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// purgeTestServer builds a Server with one edge token (scoped to acme.com) and an
// admin token, purge enabled.
func purgeTestServer(t *testing.T) (*Server, *PurgeStore) {
	t.Helper()
	authz := NewAuthz(map[string][]string{"edge-tok": {"acme.com"}})
	store := NewPurgeStore(0)
	srv := NewServer(NewCertStore(), authz).WithPurge(store, "admin-secret")
	return srv, store
}

func do(t *testing.T, h http.Handler, method, target, auth, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if auth != "" {
		r.Header.Set("Authorization", "Bearer "+auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestPurgeAPI_DisabledIs404(t *testing.T) {
	srv := NewServer(NewCertStore(), NewAuthz(map[string][]string{"edge-tok": {"acme.com"}}))
	h := srv.Handler()
	assert.Equal(t, http.StatusNotFound, do(t, h, "GET", "/v1/purges", "edge-tok", "").Code)
	assert.Equal(t, http.StatusNotFound, do(t, h, "POST", "/v1/purges", "admin-secret", `{"scope":"flush-all"}`).Code)
}

func TestPurgeAPI_GetRequiresKnownToken(t *testing.T) {
	srv, _ := purgeTestServer(t)
	h := srv.Handler()
	assert.Equal(t, http.StatusUnauthorized, do(t, h, "GET", "/v1/purges", "", "").Code)
	assert.Equal(t, http.StatusUnauthorized, do(t, h, "GET", "/v1/purges", "bogus", "").Code)
	assert.Equal(t, http.StatusOK, do(t, h, "GET", "/v1/purges", "edge-tok", "").Code)
}

func TestPurgeAPI_PostRequiresAdminToken(t *testing.T) {
	srv, _ := purgeTestServer(t)
	h := srv.Handler()
	// An edge read token must NOT be able to issue a purge.
	assert.Equal(t, http.StatusUnauthorized, do(t, h, "POST", "/v1/purges", "edge-tok", `{"scope":"flush-all"}`).Code)
	assert.Equal(t, http.StatusUnauthorized, do(t, h, "POST", "/v1/purges", "", `{"scope":"flush-all"}`).Code)
	assert.Equal(t, http.StatusOK, do(t, h, "POST", "/v1/purges", "admin-secret", `{"scope":"flush-all"}`).Code)
}

func TestPurgeAPI_PostThenGetRoundTrip(t *testing.T) {
	srv, _ := purgeTestServer(t)
	h := srv.Handler()

	rec := do(t, h, "POST", "/v1/purges", "admin-secret", `{"scope":"url","host":"acme.com","uri":"/p"}`)
	require.Equal(t, http.StatusOK, rec.Code)
	var issued map[string]uint64
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &issued))
	assert.EqualValues(t, 1, issued["seq"])

	rec = do(t, h, "GET", "/v1/purges?since=0", "edge-tok", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var got PurgeSince
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got.Entries, 1)
	assert.Equal(t, "url", got.Entries[0].Scope)
	assert.Equal(t, "/p", got.Entries[0].URI)
	assert.EqualValues(t, 1, got.MaxSeq)
}

func TestPurgeAPI_GetScopedToAllowedHosts(t *testing.T) {
	srv, store := purgeTestServer(t)
	h := srv.Handler()
	_, _ = store.Add(purgeScopeHost, "acme.com", "", "")  // edge allowed
	_, _ = store.Add(purgeScopeHost, "other.com", "", "") // edge NOT allowed
	_, _ = store.Add(purgeScopeFlushAll, "", "", "")      // everyone

	rec := do(t, h, "GET", "/v1/purges?since=0", "edge-tok", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var got PurgeSince
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	// acme.com host + flush-all, but never other.com.
	require.Len(t, got.Entries, 2)
	for _, e := range got.Entries {
		assert.NotEqual(t, "other.com", e.Host)
	}
}

func TestPurgeAPI_PrefixPostThenGet(t *testing.T) {
	srv, _ := purgeTestServer(t)
	h := srv.Handler()

	rec := do(t, h, "POST", "/v1/purges", "admin-secret", `{"scope":"prefix","host":"acme.com","uri":"/blog"}`)
	require.Equal(t, http.StatusOK, rec.Code)

	rec = do(t, h, "GET", "/v1/purges?since=0", "edge-tok", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var got PurgeSince
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got.Entries, 1)
	assert.Equal(t, "prefix", got.Entries[0].Scope)
	assert.Equal(t, "/blog", got.Entries[0].URI)
}

func TestPurgeAPI_TagPostReachesEvenUnscopedEdge(t *testing.T) {
	srv, _ := purgeTestServer(t) // edge-tok serves only acme.com
	h := srv.Handler()

	rec := do(t, h, "POST", "/v1/purges", "admin-secret", `{"scope":"tag","tag":"product-42"}`)
	require.Equal(t, http.StatusOK, rec.Code)

	// The tag purge has no host, yet the acme.com-only edge still receives it.
	rec = do(t, h, "GET", "/v1/purges?since=0", "edge-tok", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var got PurgeSince
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got.Entries, 1)
	assert.Equal(t, "tag", got.Entries[0].Scope)
	assert.Equal(t, "product-42", got.Entries[0].Tag)
}

func TestPurgeAPI_PostInvalidScopeIs400(t *testing.T) {
	srv, _ := purgeTestServer(t)
	h := srv.Handler()
	assert.Equal(t, http.StatusBadRequest, do(t, h, "POST", "/v1/purges", "admin-secret", `{"scope":"nope"}`).Code)
	assert.Equal(t, http.StatusBadRequest, do(t, h, "POST", "/v1/purges", "admin-secret", `{"scope":"host"}`).Code) // missing host
	assert.Equal(t, http.StatusBadRequest, do(t, h, "POST", "/v1/purges", "admin-secret", `not json`).Code)
}

func TestPurgeAPI_GetInvalidSinceIs400(t *testing.T) {
	srv, _ := purgeTestServer(t)
	h := srv.Handler()
	assert.Equal(t, http.StatusBadRequest, do(t, h, "GET", "/v1/purges?since=abc", "edge-tok", "").Code)
}

func TestPurgeAPI_EmptyAdminTokenLocksOut(t *testing.T) {
	// WithPurge given an empty admin token: POST can never authenticate.
	authz := NewAuthz(map[string][]string{"edge-tok": {"acme.com"}})
	srv := NewServer(NewCertStore(), authz).WithPurge(NewPurgeStore(0), "")
	h := srv.Handler()
	assert.Equal(t, http.StatusUnauthorized, do(t, h, "POST", "/v1/purges", "", `{"scope":"flush-all"}`).Code)
	assert.Equal(t, http.StatusUnauthorized, do(t, h, "POST", "/v1/purges", "anything", `{"scope":"flush-all"}`).Code)
}
