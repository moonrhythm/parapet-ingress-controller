package corazawaf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockOnURIRule denies any request whose URI contains "/attack" with 403.
const blockOnURIRule = `
SecRuleEngine On
SecRule REQUEST_URI "@contains /attack" "id:1001,phase:1,deny,status:403,msg:'blocked uri'"
`

// blockOnBodyRule denies any request whose body contains "evil" with 403.
const blockOnBodyRule = `
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_BODY "@contains evil" "id:1002,phase:2,deny,status:403,msg:'blocked body'"
`

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestPassThroughWhenNoRules(t *testing.T) {
	in := New(Options{})
	assert.False(t, in.Loaded())

	rec := httptest.NewRecorder()
	in.ServeHandler(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/attack", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestSetDirectivesEmptyUnloads(t *testing.T) {
	in := New(Options{})
	require.NoError(t, in.SetDirectives(blockOnURIRule))
	assert.True(t, in.Loaded())

	require.NoError(t, in.SetDirectives(""))
	assert.False(t, in.Loaded())

	rec := httptest.NewRecorder()
	in.ServeHandler(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/attack", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestBlockOnURI(t *testing.T) {
	var matched atomic.Int64
	in := New(Options{OnMatch: func(MatchEvent) { matched.Add(1) }})
	require.NoError(t, in.SetDirectives(blockOnURIRule))

	// blocked
	rec := httptest.NewRecorder()
	in.ServeHandler(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/attack?x=1", nil))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Positive(t, matched.Load())

	// allowed
	rec = httptest.NewRecorder()
	in.ServeHandler(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/safe", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestBadDirectivesKeepLastGood(t *testing.T) {
	in := New(Options{})
	require.NoError(t, in.SetDirectives(blockOnURIRule))

	// A syntactically invalid directive must be rejected and the prior ruleset kept.
	err := in.SetDirectives("SecRule totally not valid seclang )(")
	assert.Error(t, err)

	rec := httptest.NewRecorder()
	in.ServeHandler(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/attack", nil))
	assert.Equal(t, http.StatusForbidden, rec.Code, "last-good ruleset must stay live")
}

func TestBodyInspectionBlocksAndPreservesBody(t *testing.T) {
	in := New(Options{RequestBodyLimit: 1 << 16})
	require.NoError(t, in.SetDirectives(blockOnBodyRule))

	// malicious body -> blocked
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("payload=evil"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	in.ServeHandler(okHandler()).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// clean body -> passes through AND the upstream sees the full body
	var got string
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("payload=good&more=data"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	in.ServeHandler(echo).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "payload=good&more=data", got)
}

func TestBodyNotInspectedWhenLimitZero(t *testing.T) {
	in := New(Options{}) // RequestBodyLimit defaults to 0 -> body never read
	require.NoError(t, in.SetDirectives(blockOnBodyRule))

	var got string
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("payload=evil"))
	in.ServeHandler(echo).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "phase 2 still runs but sees no body bytes when inspection is off")
	assert.Equal(t, "payload=evil", got, "untouched body reaches upstream")
}

func TestPhase2RunsWithoutBody(t *testing.T) {
	// A phase-2 rule over the query args must fire for a bodyless GET even with
	// request-body inspection off — most CRS detections and the CRS
	// anomaly-blocking evaluation rule (949110) are phase 2, so phase 2 always
	// runs (URI/args/headers; body bytes only feed it when a limit opts in).
	const blockOnArgsPhase2 = `
SecRuleEngine On
SecRule ARGS "@contains evil" "id:1005,phase:2,deny,status:403,msg:'blocked args'"
`
	in := New(Options{}) // RequestBodyLimit 0 -> no body buffered
	require.NoError(t, in.SetDirectives(blockOnArgsPhase2))

	rec := httptest.NewRecorder()
	in.ServeHandler(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?q=evil", nil))
	assert.Equal(t, http.StatusForbidden, rec.Code, "phase-2 rules must evaluate for bodyless requests")

	rec = httptest.NewRecorder()
	in.ServeHandler(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?q=safe", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestObserveCalled(t *testing.T) {
	var calls, blocks atomic.Int64
	in := New(Options{Observe: func(_ time.Duration, blocked bool) {
		calls.Add(1)
		if blocked {
			blocks.Add(1)
		}
	}})
	require.NoError(t, in.SetDirectives(blockOnURIRule))

	in.ServeHandler(okHandler()).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/attack", nil))
	in.ServeHandler(okHandler()).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/safe", nil))
	assert.Equal(t, int64(2), calls.Load())
	assert.Equal(t, int64(1), blocks.Load())
}

func TestGlobalAndZoneCorazaBothInspectBody(t *testing.T) {
	blockOnBodyRule := `
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_BODY "@contains evil" "id:1003,phase:2,deny,status:403,msg:'blocked body'"
`

	// Global Coraza
	global := New(Options{RequestBodyLimit: 1 << 10})
	require.NoError(t, global.SetDirectives(blockOnBodyRule))

	// Zone Coraza
	zone := New(Options{RequestBodyLimit: 1 << 10})
	require.NoError(t, zone.SetDirectives(blockOnBodyRule))

	var capturedBody string
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)
		w.WriteHeader(http.StatusOK)
	})

	// Request with clean body
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("good body data"))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()

	// Global Coraza processes first, then zone — both inspect the same body
	handler := global.ServeHandler(
		zone.ServeHandler(echo),
	)
	handler.ServeHTTP(rec, req)

	// Verify the full body reaches the upstream
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "good body data", capturedBody, "full body must reach upstream despite double inspection")
}
