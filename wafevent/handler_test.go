package wafevent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func doRequest(h http.Handler, target, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHandlerAuth(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(8)
	h := NewHandler(b, "s3cret")

	assert.Equal(t, http.StatusUnauthorized, doRequest(h, "/waf/events", "").Code, "missing token")
	assert.Equal(t, http.StatusUnauthorized, doRequest(h, "/waf/events", "Bearer wrong").Code, "wrong token")
	assert.Equal(t, http.StatusUnauthorized, doRequest(h, "/waf/events", "Basic s3cret").Code, "wrong scheme")
	assert.Equal(t, http.StatusUnauthorized, doRequest(h, "/other", "").Code, "unauthenticated probes learn nothing, any path")
	assert.Equal(t, http.StatusOK, doRequest(h, "/waf/events", "Bearer s3cret").Code)
}

func TestHandlerEmptyTokenRejectsEverything(t *testing.T) {
	t.Parallel()

	// main never starts the listener without WAF_EVENTS_TOKEN; this is the
	// defense-in-depth behind that: an empty token must never authenticate.
	b, _ := newTestBuffer(8)
	h := NewHandler(b, "")

	assert.Equal(t, http.StatusUnauthorized, doRequest(h, "/waf/events", "").Code)
	assert.Equal(t, http.StatusUnauthorized, doRequest(h, "/waf/events", "Bearer ").Code)
	assert.Equal(t, http.StatusUnauthorized, doRequest(h, "/waf/events", "Bearer x").Code)
}

func TestHandlerCursorPagination(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(128)
	for range 7 {
		require.True(t, b.Append(blockEvent("ns/z", "r1"), nil))
	}
	h := NewHandler(b, "s3cret")

	var resp struct {
		Boot   string  `json:"boot"`
		Next   uint64  `json:"next"`
		Events []Event `json:"events"`
	}

	w := doRequest(h, "/waf/events?max=3", "Bearer s3cret")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Events, 3)
	assert.Equal(t, uint64(3), resp.Next)
	assert.Len(t, resp.Boot, 16)
	assert.Equal(t, "ns/z", resp.Events[0].Zone)
	assert.Equal(t, "block", resp.Events[0].Action)
	assert.Len(t, resp.Events[0].ID, 26)

	// Second page via the echoed cursor.
	w = doRequest(h, "/waf/events?after=3&boot="+resp.Boot+"&max=100", "Bearer s3cret")
	require.Equal(t, http.StatusOK, w.Code)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Events, 4)
	assert.Equal(t, uint64(7), resp.Next)

	// Exhausted: empty events array (never null), cursor echoed.
	w = doRequest(h, "/waf/events?after=7&boot="+resp.Boot, "Bearer s3cret")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"events":[]`)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Empty(t, resp.Events)
	assert.Equal(t, uint64(7), resp.Next)

	// Stale boot (pod restart) replays from the retained tail.
	w = doRequest(h, "/waf/events?after=7&boot=deadbeefdeadbeef", "Bearer s3cret")
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Events, 7)
}

func TestHandlerMaxClamp(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(2048)
	for range 30 {
		// Spread across zones to dodge the sampling caps.
		for z := range 60 {
			b.Append(blockEvent("ns/z"+string(rune('a'+z%26))+string(rune('a'+z/26)), "r"), nil)
		}
	}
	h := NewHandler(b, "s3cret")

	var resp struct {
		Events []Event `json:"events"`
	}

	// Default max is 500.
	w := doRequest(h, "/waf/events", "Bearer s3cret")
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Events, 500)

	// max is clamped to 1000.
	w = doRequest(h, "/waf/events?max=99999", "Bearer s3cret")
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Events, 1000)

	// Garbage params fall back to defaults instead of erroring.
	w = doRequest(h, "/waf/events?after=bogus&max=bogus", "Bearer s3cret")
	require.Equal(t, http.StatusOK, w.Code)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Events, 500)
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(8)
	h := NewHandler(b, "s3cret")

	r := httptest.NewRequest(http.MethodPost, "/waf/events", nil)
	r.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}
