package edge

import (
	"testing"
	"time"

	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// putEntry seeds one entry into a cache.Storage with a known Meta (for reaper tests).
func putEntry(t *testing.T, s cache.Storage, key string, m cache.Meta, body []byte) {
	t.Helper()
	m.Size = int64(len(body))
	w, err := s.Writer(key)
	require.NoError(t, err)
	_, err = w.Write(body)
	require.NoError(t, err)
	require.NoError(t, w.Commit(m))
}

func storageLen(s cache.Storage) int {
	n := 0
	s.Range(func(string, cache.Meta) bool { n++; return true })
	return n
}

// ReapOnce delegates to the parapet purge table's Reap (covered exhaustively
// there); these verify the edge wrapper end-to-end through the journal Apply path.

func TestReapOnce_DeletesInvalidatedKeepsOthers(t *testing.T) {
	s := cache.NewMemory(1 << 20)
	fresh := time.Now().Add(time.Hour).UnixNano()
	putEntry(t, s, "aa01", cache.Meta{Host: "acme.com", URI: "/a", Created: 100, FreshUntil: fresh}, []byte("x"))
	putEntry(t, s, "bb02", cache.Meta{Host: "other.com", URI: "/b", Created: 100, FreshUntil: fresh}, []byte("y"))
	putEntry(t, s, "cc03", cache.Meta{Host: "acme.com", URI: "/c", Created: 250, FreshUntil: fresh}, []byte("z")) // created AFTER the purge

	clk := &stepClock{}
	clk.set(200)
	tbl := newClockedTable(t, "", clk)
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 1, Scope: ScopeHost, Host: "acme.com"}}, 1)) // host epoch 200

	clk.set(300)
	ReapOnce(s, tbl)

	_, _, okA := s.Get("aa01")
	assert.False(t, okA, "acme.com /a (created 100 <= 200) reaped")
	_, _, okB := s.Get("bb02")
	assert.True(t, okB, "other.com untouched (different host)")
	_, _, okC := s.Get("cc03")
	assert.True(t, okC, "acme.com /c (created 250 > 200) survives — not over-reaped")
	assert.EqualValues(t, 1, tbl.Stats().HostRecs, "record kept (retirement intentionally not done)")
}

func TestReapOnce_GlobalReapsAllIncludingEmptyHost(t *testing.T) {
	s := cache.NewMemory(1 << 20)
	fresh := time.Now().Add(time.Hour).UnixNano()
	putEntry(t, s, "aa01", cache.Meta{Host: "", URI: "/old", Created: 100, FreshUntil: fresh}, []byte("x")) // no Host
	putEntry(t, s, "bb02", cache.Meta{Host: "a.com", URI: "/y", Created: 100, FreshUntil: fresh}, []byte("y"))

	clk := &stepClock{}
	clk.set(200)
	tbl := newClockedTable(t, "", clk)
	require.NoError(t, tbl.FlushAll(1)) // global epoch 200

	clk.set(300)
	ReapOnce(s, tbl)
	assert.Zero(t, storageLen(s), "flush-all reaps every entry, even one with an empty Host")
}

func TestReapOnce_TagReapsAcrossHosts(t *testing.T) {
	s := cache.NewMemory(1 << 20)
	fresh := time.Now().Add(time.Hour).UnixNano()
	putEntry(t, s, "aa01", cache.Meta{Host: "shop.com", URI: "/p1", Tags: []string{"product-42"}, Created: 100, FreshUntil: fresh}, []byte("x"))
	putEntry(t, s, "bb02", cache.Meta{Host: "blog.com", URI: "/post", Tags: []string{"product-42"}, Created: 100, FreshUntil: fresh}, []byte("y"))
	putEntry(t, s, "cc03", cache.Meta{Host: "shop.com", URI: "/p2", Tags: []string{"product-99"}, Created: 100, FreshUntil: fresh}, []byte("z"))

	clk := &stepClock{}
	clk.set(200)
	tbl := newClockedTable(t, "", clk)
	require.NoError(t, tbl.Apply([]PurgeEntry{{Seq: 1, Scope: ScopeTag, Tag: "product-42"}}, 1))

	clk.set(300)
	ReapOnce(s, tbl)

	_, _, okA := s.Get("aa01")
	assert.False(t, okA, "tagged product-42 reaped (shop.com)")
	_, _, okB := s.Get("bb02")
	assert.False(t, okB, "tagged product-42 reaped across hosts (blog.com)")
	_, _, okC := s.Get("cc03")
	assert.True(t, okC, "product-99 untouched")
}

func TestReapOnce_NoPurgesIsNoOp(t *testing.T) {
	s := cache.NewMemory(1 << 20)
	fresh := time.Now().Add(time.Hour).UnixNano()
	putEntry(t, s, "aa01", cache.Meta{Host: "a.com", URI: "/a", Created: 100, FreshUntil: fresh}, []byte("x"))

	tbl, err := NewPurgeTable("", 0)
	require.NoError(t, err)
	ReapOnce(s, tbl)
	assert.Equal(t, 1, storageLen(s), "nothing purged -> nothing reaped")
}
