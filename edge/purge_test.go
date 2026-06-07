package edge

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// epochFor is the table's hook applied to a synthetic request for method/url.
func epochFor(t *PurgeTable, method, rawurl string) int64 {
	return t.InvalidatedAfter(httptest.NewRequest(method, rawurl, nil), cache.Meta{})
}

// fixedClock pins the table's clock for deterministic epochs.
func fixedClock(t *PurgeTable, nanos int64) {
	t.nowNanos = func() int64 { return nanos }
}

func TestPurge_ScopesAndMax(t *testing.T) {
	tbl, err := NewPurgeTable("", 0)
	require.NoError(t, err)
	fixedClock(tbl, 1000)

	// url scope: only the exact url is invalidated.
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 1, Scope: ScopeURL, Host: "acme.com", URI: "/a"}}, 1))
	assert.EqualValues(t, 1000, epochFor(tbl, "GET", "http://acme.com/a"))
	assert.EqualValues(t, 0, epochFor(tbl, "GET", "http://acme.com/b"), "sibling url untouched")

	// host scope: every url under the host. A later epoch wins via max.
	fixedClock(tbl, 2000)
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 2, Scope: ScopeHost, Host: "acme.com"}}, 2))
	assert.EqualValues(t, 2000, epochFor(tbl, "GET", "http://acme.com/b"))
	assert.EqualValues(t, 2000, epochFor(tbl, "GET", "http://acme.com/a"), "host epoch > url epoch wins")
	assert.EqualValues(t, 0, epochFor(tbl, "GET", "http://other.com/a"), "other host untouched")

	// global scope: everything.
	fixedClock(tbl, 3000)
	require.NoError(t, tbl.FlushAll(3))
	assert.EqualValues(t, 3000, epochFor(tbl, "GET", "http://other.com/a"))
}

func TestPurge_URLCoversMethodSchemeVariant(t *testing.T) {
	tbl, _ := NewPurgeTable("", 0)
	fixedClock(tbl, 7000)
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 1, Scope: ScopeURL, Host: "acme.com", URI: "/p?x=1"}}, 1))

	// Same host+uri, regardless of method/scheme, resolves to the same key.
	assert.EqualValues(t, 7000, epochFor(tbl, "GET", "http://acme.com/p?x=1"))
	assert.EqualValues(t, 7000, epochFor(tbl, "HEAD", "http://acme.com/p?x=1"))
	assert.EqualValues(t, 7000, epochFor(tbl, "GET", "https://acme.com/p?x=1"))
	// Different query is a different url.
	assert.EqualValues(t, 0, epochFor(tbl, "GET", "http://acme.com/p?x=2"))
}

func TestPurge_HostNormalizationMatchesCacheKey(t *testing.T) {
	tbl, _ := NewPurgeTable("", 0)
	fixedClock(tbl, 5000)
	// Purge issued with mixed case + port; lookups with other case/port must match.
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 1, Scope: ScopeHost, Host: "ACME.com:443"}}, 1))
	assert.EqualValues(t, 5000, epochFor(tbl, "GET", "http://acme.com/x"))
	assert.EqualValues(t, 5000, epochFor(tbl, "GET", "http://Acme.COM:8443/x"))
}

func TestPurge_MonotonicClampOnClockStepBack(t *testing.T) {
	tbl, _ := NewPurgeTable("", 0)
	fixedClock(tbl, 10_000)
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 1, Scope: ScopeHost, Host: "a.com"}}, 1))
	assert.EqualValues(t, 10_000, epochFor(tbl, "GET", "http://a.com/"))

	// Clock steps back; a new purge must not get a lower epoch.
	fixedClock(tbl, 9_000)
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 2, Scope: ScopeHost, Host: "b.com"}}, 2))
	assert.EqualValues(t, 10_000, epochFor(tbl, "GET", "http://b.com/"), "clamped to highWater, not the stepped-back clock")

	// A flush after a step-back is also clamped.
	fixedClock(tbl, 8_000)
	require.NoError(t, tbl.FlushAll(3))
	assert.GreaterOrEqual(t, epochFor(tbl, "GET", "http://c.com/"), int64(10_000))
}

func TestPurge_ApplyIdempotentByCursor(t *testing.T) {
	tbl, _ := NewPurgeTable("", 0)
	fixedClock(tbl, 1000)
	require.NoError(t, tbl.Apply([]PurgeEntry{
		{Seq: 1, Scope: ScopeURL, Host: "a.com", URI: "/x"},
		{Seq: 2, Scope: ScopeURL, Host: "a.com", URI: "/y"},
	}, 2))
	assert.EqualValues(t, 2, tbl.Cursor())

	// Re-deliver seq 1-2 plus a new seq 3 with a later clock; only seq 3 applies.
	fixedClock(tbl, 9000)
	require.NoError(t, tbl.Apply([]PurgeEntry{
		{Seq: 1, Scope: ScopeURL, Host: "a.com", URI: "/x"},
		{Seq: 2, Scope: ScopeURL, Host: "a.com", URI: "/y"},
		{Seq: 3, Scope: ScopeURL, Host: "a.com", URI: "/z"},
	}, 3))
	assert.EqualValues(t, 1000, epochFor(tbl, "GET", "http://a.com/x"), "already-applied entry not re-stamped")
	assert.EqualValues(t, 9000, epochFor(tbl, "GET", "http://a.com/z"), "new entry applied")
	assert.EqualValues(t, 3, tbl.Cursor())
}

func TestPurge_ApplyAdvancesCursorOnGap(t *testing.T) {
	tbl, _ := NewPurgeTable("", 0)
	// An empty batch with a higher maxSeq still advances the cursor.
	require.NoError(t, tbl.Apply(nil, 42))
	assert.EqualValues(t, 42, tbl.Cursor())
	// Cursor never regresses.
	require.NoError(t, tbl.Apply(nil, 10))
	assert.EqualValues(t, 42, tbl.Cursor())
}

func TestPurge_FlushAllClearsAndSupersedes(t *testing.T) {
	tbl, _ := NewPurgeTable("", 0)
	fixedClock(tbl, 1000)
	require.NoError(t, tbl.Apply([]PurgeEntry{
		{Seq: 1, Scope: ScopeURL, Host: "a.com", URI: "/x"},
		{Seq: 2, Scope: ScopeHost, Host: "b.com"},
		{Seq: 3, Scope: ScopePrefix, Host: "c.com", URI: "/blog"},
		{Seq: 4, Scope: ScopeTag, Tag: "t1"},
	}, 4))
	fixedClock(tbl, 5000)
	require.NoError(t, tbl.FlushAll(5))

	st := tbl.Stats()
	assert.Zero(t, st.HostRecs, "host map cleared on flush")
	assert.Zero(t, st.URLRecs, "url map cleared on flush")
	assert.Zero(t, st.PrefixRecs, "prefix map cleared on flush")
	assert.Zero(t, st.TagRecs, "tag map cleared on flush")
	assert.EqualValues(t, 5000, epochFor(tbl, "GET", "http://anything.com/q"))
}

func TestPurge_CapFoldBoundsMemory(t *testing.T) {
	tbl, _ := NewPurgeTable("", 2) // tiny cap to force a fold
	fixedClock(tbl, 1000)
	require.NoError(t, tbl.Apply([]PurgeEntry{
		{Seq: 1, Scope: ScopeURL, Host: "a.com", URI: "/1"},
		{Seq: 2, Scope: ScopeURL, Host: "a.com", URI: "/2"},
		{Seq: 3, Scope: ScopeURL, Host: "a.com", URI: "/3"}, // overflow -> fold
	}, 3))

	st := tbl.Stats()
	assert.Zero(t, st.URLRecs, "overflowing url map folded to global")
	assert.EqualValues(t, 1, st.Folds)
	// Conservative: the folded urls are still invalidated (via the global epoch).
	assert.EqualValues(t, 1000, epochFor(tbl, "GET", "http://a.com/1"))
	assert.EqualValues(t, 1000, epochFor(tbl, "GET", "http://a.com/2"))
}

func TestPurge_InvalidatedAfterMetaMatchesRequest(t *testing.T) {
	tbl, _ := NewPurgeTable("", 0)
	fixedClock(tbl, 4000)
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 1, Scope: ScopeURL, Host: "acme.com", URI: "/p?x=1"}}, 1))

	// The reaper's Meta-based lookup must agree with the request-based hook for the
	// same host+uri (Meta.Host is already normalized; normHost is idempotent).
	m := cache.Meta{Host: "acme.com", URI: "/p?x=1"}
	assert.EqualValues(t, 4000, tbl.InvalidatedAfterMeta(m))
	assert.Equal(t, epochFor(tbl, "GET", "http://acme.com/p?x=1"), tbl.InvalidatedAfterMeta(m))
	// A different uri doesn't match.
	assert.EqualValues(t, 0, tbl.InvalidatedAfterMeta(cache.Meta{Host: "acme.com", URI: "/p?x=2"}))
	// An empty-Host (old) entry matches only the global scope.
	assert.EqualValues(t, 0, tbl.InvalidatedAfterMeta(cache.Meta{Host: "", URI: "/p?x=1"}))
}

func TestPurge_PrefixScope(t *testing.T) {
	tbl, _ := NewPurgeTable("", 0)
	fixedClock(tbl, 1000)
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 1, Scope: ScopePrefix, Host: "acme.com", URI: "/blog"}}, 1))

	// Covered: the prefix itself, anything under it, and any query variant (path-only).
	assert.EqualValues(t, 1000, epochFor(tbl, "GET", "http://acme.com/blog"))
	assert.EqualValues(t, 1000, epochFor(tbl, "GET", "http://acme.com/blog/post-1"))
	assert.EqualValues(t, 1000, epochFor(tbl, "GET", "http://acme.com/blog/post-1?utm=x"))
	// Not covered: boundary (/blogger), a sibling path, or another host.
	assert.EqualValues(t, 0, epochFor(tbl, "GET", "http://acme.com/blogger"), "path boundary respected")
	assert.EqualValues(t, 0, epochFor(tbl, "GET", "http://acme.com/about"))
	assert.EqualValues(t, 0, epochFor(tbl, "GET", "http://other.com/blog/x"), "prefix is host-scoped")
}

func TestPurge_PrefixNormalizationAndRoot(t *testing.T) {
	tbl, _ := NewPurgeTable("", 0)
	fixedClock(tbl, 2000)
	// Trailing slash is normalized away: "/docs/" purges the same section as "/docs".
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 1, Scope: ScopePrefix, Host: "a.com", URI: "/docs/"}}, 1))
	assert.EqualValues(t, 2000, epochFor(tbl, "GET", "http://a.com/docs"))
	assert.EqualValues(t, 2000, epochFor(tbl, "GET", "http://a.com/docs/intro"))
	assert.EqualValues(t, 0, epochFor(tbl, "GET", "http://a.com/docsource"))

	// "/" is the whole-host prefix.
	fixedClock(tbl, 3000)
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 2, Scope: ScopePrefix, Host: "b.com", URI: "/"}}, 2))
	assert.EqualValues(t, 3000, epochFor(tbl, "GET", "http://b.com/anything/here"))
}

func TestPurge_PrefixRepeatUpdatesEpochInPlace(t *testing.T) {
	tbl, _ := NewPurgeTable("", 0)
	fixedClock(tbl, 1000)
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 1, Scope: ScopePrefix, Host: "a.com", URI: "/x"}}, 1))
	fixedClock(tbl, 5000)
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 2, Scope: ScopePrefix, Host: "a.com", URI: "/x"}}, 2))
	assert.EqualValues(t, 1, tbl.Stats().PrefixRecs, "same prefix updates in place, no duplicate record")
	assert.EqualValues(t, 5000, epochFor(tbl, "GET", "http://a.com/x/y"), "epoch advanced to the latest purge")
}

func TestPurge_PrefixPersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purge-state")
	t1, err := NewPurgeTable(path, 0)
	require.NoError(t, err)
	fixedClock(t1, 4000)
	require.NoError(t, t1.Apply([]PurgeEntry{{Seq: 1, Scope: ScopePrefix, Host: "a.com", URI: "/sec"}}, 1))

	t2, err := NewPurgeTable(path, 0)
	require.NoError(t, err)
	assert.EqualValues(t, 4000, epochFor(t2, "GET", "http://a.com/sec/page"), "prefix record survives reload")
	assert.EqualValues(t, 1, t2.Stats().PrefixRecs)
}

func TestPurge_PrefixCapFold(t *testing.T) {
	tbl, _ := NewPurgeTable("", 2) // tiny cap
	fixedClock(tbl, 1000)
	require.NoError(t, tbl.Apply([]PurgeEntry{
		{Seq: 1, Scope: ScopePrefix, Host: "a.com", URI: "/1"},
		{Seq: 2, Scope: ScopePrefix, Host: "a.com", URI: "/2"},
		{Seq: 3, Scope: ScopePrefix, Host: "a.com", URI: "/3"}, // overflow -> fold to global
	}, 3))
	assert.Zero(t, tbl.Stats().PrefixRecs, "overflowing prefix records folded into global")
	assert.EqualValues(t, 1, tbl.Stats().Folds)
	assert.EqualValues(t, 1000, epochFor(tbl, "GET", "http://a.com/1"), "still invalidated via the global epoch")
}

func TestPurge_TagScope(t *testing.T) {
	tbl, _ := NewPurgeTable("", 0)
	fixedClock(tbl, 1000)
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 1, Scope: ScopeTag, Tag: "product-42"}}, 1))

	// Any entry carrying the surrogate key is invalidated, regardless of host/url.
	assert.EqualValues(t, 1000, tbl.InvalidatedAfterMeta(cache.Meta{Host: "shop.com", URI: "/p", Tags: []string{"product-42"}}))
	assert.EqualValues(t, 1000, tbl.InvalidatedAfterMeta(cache.Meta{Host: "other.com", URI: "/x", Tags: []string{"a", "product-42"}}))
	// Entries without the tag are untouched.
	assert.EqualValues(t, 0, tbl.InvalidatedAfterMeta(cache.Meta{Host: "shop.com", URI: "/p", Tags: []string{"category-shoes"}}))
	assert.EqualValues(t, 0, tbl.InvalidatedAfterMeta(cache.Meta{Host: "shop.com", URI: "/p"}))
}

func TestPurge_TagPersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purge-state")
	t1, err := NewPurgeTable(path, 0)
	require.NoError(t, err)
	fixedClock(t1, 6000)
	require.NoError(t, t1.Apply([]PurgeEntry{{Seq: 1, Scope: ScopeTag, Tag: "sku-7"}}, 1))

	t2, err := NewPurgeTable(path, 0)
	require.NoError(t, err)
	assert.EqualValues(t, 6000, t2.InvalidatedAfterMeta(cache.Meta{Tags: []string{"sku-7"}}), "tag record survives reload")
	assert.EqualValues(t, 1, t2.Stats().TagRecs)
}

func TestPurge_FlushAllRealignsCursorDown(t *testing.T) {
	tbl, _ := NewPurgeTable("", 0)
	require.NoError(t, tbl.Apply(nil, 500)) // cursor 500 (persisted against an old journal)
	require.NoError(t, tbl.FlushAll(3))     // journal reset: realign the cursor DOWN to maxSeq
	assert.EqualValues(t, 3, tbl.Cursor(), "a reset flush realigns the cursor down so it can't re-flush forever")
}

func TestPurge_PersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purge-state")

	t1, err := NewPurgeTable(path, 0)
	require.NoError(t, err)
	fixedClock(t1, 5000)
	require.NoError(t, t1.Apply([]PurgeEntry{
		{Seq: 7, Scope: ScopeHost, Host: "a.com"},
		{Seq: 8, Scope: ScopeURL, Host: "b.com", URI: "/p"},
	}, 8))

	// Reopen: state + cursor + highWater survive.
	t2, err := NewPurgeTable(path, 0)
	require.NoError(t, err)
	assert.EqualValues(t, 8, t2.Cursor())
	assert.EqualValues(t, 5000, epochFor(t2, "GET", "http://a.com/anything"))
	assert.EqualValues(t, 5000, epochFor(t2, "GET", "http://b.com/p"))

	// highWater restored: a purge under a stepped-back clock still clamps up.
	fixedClock(t2, 1)
	require.NoError(t, t2.Apply([]PurgeEntry{{Seq: 9, Scope: ScopeHost, Host: "c.com"}}, 9))
	assert.EqualValues(t, 5000, epochFor(t2, "GET", "http://c.com/"), "highWater reloaded")
}

func TestPurge_CorruptStateResetsToEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purge-state")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o644))

	tbl, err := NewPurgeTable(path, 0)
	require.Error(t, err, "corrupt state is surfaced for logging")
	assert.EqualValues(t, 0, tbl.Cursor(), "reset to a clean table (next poll gaps -> flush)")
	assert.EqualValues(t, 0, epochFor(tbl, "GET", "http://a.com/"))
}

func TestPurge_MissingStateIsCleanStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist")
	tbl, err := NewPurgeTable(path, 0)
	require.NoError(t, err)
	assert.EqualValues(t, 0, tbl.Cursor())
}
