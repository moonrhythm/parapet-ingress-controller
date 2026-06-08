package edge

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/moonrhythm/parapet/pkg/cache/purge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The scope mechanics (host/url/prefix/tag matching, the monotonic clamp, the
// cap-fold, the active gate) live in and are tested by parapet/pkg/cache/purge.
// These tests cover the control-plane DISTRIBUTION layer this package adds: the
// journal cursor, Apply's idempotency, FlushAll's cursor handling, and the
// {snapshot, cursor} persistence.

// stepClock is a manually-advanced clock for deterministic epochs.
type stepClock struct{ n atomic.Int64 }

func (c *stepClock) now() time.Time { return time.Unix(0, c.n.Load()) }
func (c *stepClock) set(n int64)    { c.n.Store(n) }

func newClockedTable(t *testing.T, path string, clk *stepClock) *PurgeTable {
	t.Helper()
	tbl, err := NewPurgeTable(path, 0, purge.WithClock(clk.now))
	require.NoError(t, err)
	return tbl
}

// epochFor applies the lookup hook to a synthetic request.
func epochFor(t *PurgeTable, method, rawurl string) int64 {
	return t.InvalidatedAfter(httptest.NewRequest(method, rawurl, nil), cache.Meta{})
}

func TestPurge_ApplyDispatchesScopes(t *testing.T) {
	clk := &stepClock{}
	clk.set(1000)
	tbl := newClockedTable(t, "", clk)

	require.NoError(t, tbl.Apply([]PurgeEntry{
		{Seq: 1, Scope: ScopeURL, Host: "acme.com", URI: "/a"},
		{Seq: 2, Scope: ScopeHost, Host: "h.com"},
		{Seq: 3, Scope: ScopePrefix, Host: "p.com", URI: "/blog"},
		{Seq: 4, Scope: ScopeTag, Tag: "t1"},
	}, 4))

	assert.EqualValues(t, 1000, epochFor(tbl, "GET", "http://acme.com/a"), "url scope dispatched")
	assert.EqualValues(t, 0, epochFor(tbl, "GET", "http://acme.com/b"), "sibling url untouched")
	assert.EqualValues(t, 1000, epochFor(tbl, "GET", "http://h.com/x"), "host scope dispatched")
	assert.EqualValues(t, 1000, epochFor(tbl, "GET", "http://p.com/blog/post"), "prefix scope dispatched")
	assert.EqualValues(t, 1000, tbl.InvalidatedAfterMeta(cache.Meta{Tags: []string{"t1"}}), "tag scope dispatched")
	assert.EqualValues(t, 4, tbl.Cursor())

	// flush-all dispatch.
	clk.set(2000)
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 5, Scope: ScopeFlushAll}}, 5))
	assert.EqualValues(t, 2000, epochFor(tbl, "GET", "http://anything.com/q"), "flush-all dispatched")
}

func TestPurge_ApplyIdempotentByCursor(t *testing.T) {
	clk := &stepClock{}
	clk.set(1000)
	tbl := newClockedTable(t, "", clk)
	require.NoError(t, tbl.Apply([]PurgeEntry{
		{Seq: 1, Scope: ScopeURL, Host: "a.com", URI: "/x"},
		{Seq: 2, Scope: ScopeURL, Host: "a.com", URI: "/y"},
	}, 2))
	assert.EqualValues(t, 2, tbl.Cursor())

	// Re-deliver seq 1-2 plus a new seq 3 under a later clock; only seq 3 applies.
	clk.set(9000)
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
	tbl, err := NewPurgeTable("", 0)
	require.NoError(t, err)
	// An empty batch with a higher maxSeq still advances the cursor.
	require.NoError(t, tbl.Apply(nil, 42))
	assert.EqualValues(t, 42, tbl.Cursor())
	// Cursor never regresses on a normal apply.
	require.NoError(t, tbl.Apply(nil, 10))
	assert.EqualValues(t, 42, tbl.Cursor())
}

func TestPurge_FlushAllRealignsCursorDown(t *testing.T) {
	tbl, err := NewPurgeTable("", 0)
	require.NoError(t, err)
	require.NoError(t, tbl.Apply(nil, 500)) // cursor 500 (persisted against an old journal)
	require.NoError(t, tbl.FlushAll(3))     // journal reset: realign the cursor DOWN to maxSeq
	assert.EqualValues(t, 3, tbl.Cursor(), "a reset flush realigns the cursor down so it can't re-flush forever")
}

func TestPurge_PersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purge-state")
	clk := &stepClock{}
	clk.set(5000)
	t1 := newClockedTable(t, path, clk)
	require.NoError(t, t1.Apply([]PurgeEntry{
		{Seq: 7, Scope: ScopeHost, Host: "a.com"},
		{Seq: 8, Scope: ScopeURL, Host: "b.com", URI: "/p"},
		{Seq: 9, Scope: ScopePrefix, Host: "c.com", URI: "/blog"},
		{Seq: 10, Scope: ScopeTag, Tag: "sku-7"},
	}, 10))

	// Reopen under a stepped-back clock: state + cursor + highWater survive.
	clk2 := &stepClock{}
	clk2.set(1)
	t2 := newClockedTable(t, path, clk2)
	assert.EqualValues(t, 10, t2.Cursor())
	assert.EqualValues(t, 5000, epochFor(t2, "GET", "http://a.com/anything"))
	assert.EqualValues(t, 5000, epochFor(t2, "GET", "http://b.com/p"))
	assert.EqualValues(t, 5000, epochFor(t2, "GET", "http://c.com/blog/post"))
	assert.EqualValues(t, 5000, t2.InvalidatedAfterMeta(cache.Meta{Tags: []string{"sku-7"}}))

	// highWater restored: a new purge under the stepped-back clock still clamps up.
	require.NoError(t, t2.Apply([]PurgeEntry{{Seq: 11, Scope: ScopeHost, Host: "d.com"}}, 11))
	assert.EqualValues(t, 5000, epochFor(t2, "GET", "http://d.com/"), "highWater reloaded")
}

func TestPurge_PersistStaleVersionSkipped(t *testing.T) {
	// persist() runs the fsync OFF the table lock and must drop a stale snapshot
	// whose newer successor already landed, so an older Apply can't clobber a newer
	// one's on-disk state.
	path := filepath.Join(t.TempDir(), "purge-state")
	clk := &stepClock{}
	clk.set(1000)
	tbl := newClockedTable(t, path, clk)

	// Capture two ordered snapshots (newer = v2).
	tbl.mu.Lock()
	tbl.tbl.PurgeHost("a.com")
	snap1, ver1 := tbl.snapshotLocked()
	tbl.tbl.PurgeHost("b.com")
	snap2, ver2 := tbl.snapshotLocked()
	tbl.mu.Unlock()
	require.Greater(t, ver2, ver1)

	// Land the NEWER one first, then try the older — the older must be skipped.
	require.NoError(t, tbl.persist(snap2, ver2))
	require.NoError(t, tbl.persist(snap1, ver1))

	reloaded, err := NewPurgeTable(path, 0)
	require.NoError(t, err)
	assert.Positive(t, reloaded.InvalidatedAfterMeta(cache.Meta{Host: "b.com"}), "newer snapshot survived")
	assert.Positive(t, reloaded.InvalidatedAfterMeta(cache.Meta{Host: "a.com"}), "stale persist did not roll the file back")
}

func TestPurge_GateActiveAfterReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purge-state")
	clk := &stepClock{}
	clk.set(2000)
	t1 := newClockedTable(t, path, clk)
	require.NoError(t, t1.Apply([]PurgeEntry{{Seq: 1, Scope: ScopeHost, Host: "a.com"}}, 1))

	// A reload must re-open the gate; else lookups would short-circuit to 0 and
	// silently under-invalidate after a restart.
	t2, err := NewPurgeTable(path, 0)
	require.NoError(t, err)
	assert.EqualValues(t, 2000, t2.InvalidatedAfterMeta(cache.Meta{Host: "a.com", URI: "/x"}))
	assert.EqualValues(t, 0, t2.InvalidatedAfterMeta(cache.Meta{Host: "other.com", URI: "/x"}))
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

// A state file written by the PRE-MIGRATION code (flat host/url/prefix/tag/global
// + cursor) must load unchanged, so an in-place upgrade doesn't gap the cursor and
// trigger a fleet-wide flush.
func TestPurge_LoadsPreMigrationFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purge-state")
	old := `{"global":5000,` +
		`"host":{"a.com":5000},` +
		`"url":{},` +
		`"prefix":{"c.com":[{"prefix":"/blog","epoch":5000}]},` +
		`"tag":{"sku-7":5000},` +
		`"cursor":8}`
	require.NoError(t, os.WriteFile(path, []byte(old), 0o644))

	tbl, err := NewPurgeTable(path, 0)
	require.NoError(t, err)
	assert.EqualValues(t, 8, tbl.Cursor(), "cursor preserved")
	assert.EqualValues(t, 5000, epochFor(tbl, "GET", "http://a.com/x"), "host record loaded")
	assert.EqualValues(t, 5000, epochFor(tbl, "GET", "http://c.com/blog/post"), "prefix record loaded")
	assert.EqualValues(t, 5000, tbl.InvalidatedAfterMeta(cache.Meta{Tags: []string{"sku-7"}}), "tag record loaded")
	assert.EqualValues(t, 5000, epochFor(tbl, "GET", "http://anything.com/"), "global loaded")
}
