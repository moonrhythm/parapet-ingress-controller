package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchPurges200ParsesPayloadAndSendsCursor(t *testing.T) {
	var gotSince, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/purges", r.URL.Path)
		gotSince = r.URL.Query().Get("since")
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"entries":[{"seq":3,"scope":"url","host":"acme.com","uri":"/a"},{"seq":4,"scope":"host","host":"acme.com"}],"max_seq":4,"flush_required":false}`))
	}))
	defer srv.Close()

	cp, _ := NewCpClient(srv.URL, "tok-9", nil)
	res, err := cp.FetchPurges(2)
	require.NoError(t, err)
	assert.False(t, res.Disabled)
	assert.False(t, res.FlushRequired)
	assert.EqualValues(t, 4, res.MaxSeq)
	require.Len(t, res.Entries, 2)
	assert.Equal(t, ScopeURL, res.Entries[0].Scope)
	assert.Equal(t, "/a", res.Entries[0].URI)
	assert.Equal(t, "2", gotSince)
	assert.Equal(t, "Bearer tok-9", gotAuth)
}

func TestFetchPurges404IsDisabledNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	cp, _ := NewCpClient(srv.URL, "t", nil)
	res, err := cp.FetchPurges(0)
	require.NoError(t, err, "404 is a clean disabled state, not an error")
	assert.True(t, res.Disabled)
}

func TestFetchPurgesFlushRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"entries":[],"max_seq":99,"flush_required":true}`))
	}))
	defer srv.Close()
	cp, _ := NewCpClient(srv.URL, "t", nil)
	res, err := cp.FetchPurges(1)
	require.NoError(t, err)
	assert.True(t, res.FlushRequired)
	assert.EqualValues(t, 99, res.MaxSeq)
}

func TestFetchPurgesNon200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	cp, _ := NewCpClient(srv.URL, "t", nil)
	_, err := cp.FetchPurges(0)
	assert.Error(t, err, "5xx is a fail-static error")
}

func TestRefreshPurgeOnce_AppliesAndAdvancesCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"entries":[{"seq":1,"scope":"url","host":"acme.com","uri":"/x"}],"max_seq":1,"flush_required":false}`))
	}))
	defer srv.Close()
	cp, _ := NewCpClient(srv.URL, "t", nil)
	tbl, _ := NewPurgeTable("", 0)

	RefreshPurgeOnce(cp, tbl)
	assert.EqualValues(t, 1, tbl.Cursor())
	assert.Positive(t, epochFor(tbl, "GET", "http://acme.com/x"), "purged url has a non-zero invalidation epoch")
}

func TestRefreshPurgeOnce_FlushRequiredBumpsGlobal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"entries":[],"max_seq":50,"flush_required":true}`))
	}))
	defer srv.Close()
	cp, _ := NewCpClient(srv.URL, "t", nil)
	tbl, _ := NewPurgeTable("", 0)

	RefreshPurgeOnce(cp, tbl)
	assert.EqualValues(t, 50, tbl.Cursor())
	assert.Positive(t, epochFor(tbl, "GET", "http://anything.com/q"), "flush-all sets a global epoch")
}

func TestRefreshPurgeOnce_MaxSeqBelowCursorForcesFlush(t *testing.T) {
	// Defense-in-depth for an OLD CP that doesn't set flush_required on a journal reset
	// but reports a max_seq below our cursor: the edge must still flush + realign.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"entries":[],"max_seq":3,"flush_required":false}`))
	}))
	defer srv.Close()
	cp, _ := NewCpClient(srv.URL, "t", nil)
	tbl, _ := NewPurgeTable("", 0)
	require.NoError(t, tbl.Apply(nil, 500)) // cursor 500, ahead of the reset journal

	RefreshPurgeOnce(cp, tbl)
	assert.EqualValues(t, 3, tbl.Cursor(), "defense-in-depth flush realigns the cursor down")
	assert.Positive(t, epochFor(tbl, "GET", "http://x.com/y"), "flush bumped the global epoch")
}

func TestRefreshPurgeOnce_FetchErrorIsFailStatic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	cp, _ := NewCpClient(srv.URL, "t", nil)
	tbl, _ := NewPurgeTable("", 0)
	// Seed a cursor so we can prove it isn't disturbed by a failed poll.
	require.NoError(t, tbl.Apply(nil, 7))

	RefreshPurgeOnce(cp, tbl)
	assert.EqualValues(t, 7, tbl.Cursor(), "a failed poll keeps the cursor (fail-static)")
}
