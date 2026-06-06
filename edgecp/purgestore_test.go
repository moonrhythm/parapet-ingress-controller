package edgecp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func allowAll(string) bool  { return true }
func allowNone(string) bool { return false }

func TestPurgeStore_AddAndSinceFromZero(t *testing.T) {
	s := NewPurgeStore(0)
	seq1, ok := s.Add(purgeScopeURL, "acme.com", "/a")
	require.True(t, ok)
	seq2, ok := s.Add(purgeScopeHost, "acme.com", "")
	require.True(t, ok)
	seq3, ok := s.Add(purgeScopeFlushAll, "", "")
	require.True(t, ok)
	assert.EqualValues(t, 1, seq1)
	assert.EqualValues(t, 2, seq2)
	assert.EqualValues(t, 3, seq3)

	res := s.Since(0, allowAll)
	assert.False(t, res.FlushRequired)
	assert.EqualValues(t, 3, res.MaxSeq)
	require.Len(t, res.Entries, 3)
	assert.Equal(t, purgeScopeURL, res.Entries[0].Scope)
	assert.Equal(t, "/a", res.Entries[0].URI)
}

func TestPurgeStore_SinceIncremental(t *testing.T) {
	s := NewPurgeStore(0)
	_, _ = s.Add(purgeScopeURL, "a.com", "/1")
	_, _ = s.Add(purgeScopeURL, "a.com", "/2")
	_, _ = s.Add(purgeScopeURL, "a.com", "/3")

	res := s.Since(2, allowAll)
	require.Len(t, res.Entries, 1, "only entries with seq > cursor")
	assert.EqualValues(t, 3, res.Entries[0].Seq)
	assert.EqualValues(t, 3, res.MaxSeq)
}

func TestPurgeStore_EmptyJournalNoGap(t *testing.T) {
	s := NewPurgeStore(0)
	res := s.Since(0, allowAll)
	assert.False(t, res.FlushRequired)
	assert.Empty(t, res.Entries)
	assert.EqualValues(t, 0, res.MaxSeq)
}

func TestPurgeStore_ScopingByHost(t *testing.T) {
	s := NewPurgeStore(0)
	_, _ = s.Add(purgeScopeHost, "a.com", "")
	_, _ = s.Add(purgeScopeHost, "b.com", "")
	_, _ = s.Add(purgeScopeFlushAll, "", "")

	// An edge allowed only a.com sees its host entry + the flush-all, not b.com.
	allowA := func(h string) bool { return h == "a.com" }
	res := s.Since(0, allowA)
	require.Len(t, res.Entries, 2)
	scopes := map[string]string{}
	for _, e := range res.Entries {
		scopes[e.Scope] = e.Host
	}
	assert.Equal(t, "a.com", scopes[purgeScopeHost])
	_, hasFlush := scopes[purgeScopeFlushAll]
	assert.True(t, hasFlush, "flush-all reaches every edge regardless of host scope")
}

func TestPurgeStore_FlushAllAlwaysDeliveredEvenToDenyAll(t *testing.T) {
	s := NewPurgeStore(0)
	_, _ = s.Add(purgeScopeHost, "a.com", "")
	_, _ = s.Add(purgeScopeFlushAll, "", "")
	res := s.Since(0, allowNone)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, purgeScopeFlushAll, res.Entries[0].Scope)
}

func TestPurgeStore_GapTriggersFlushRequired(t *testing.T) {
	s := NewPurgeStore(2) // retain only the 2 newest
	for i := 0; i < 5; i++ {
		_, ok := s.Add(purgeScopeURL, "a.com", "/x")
		require.True(t, ok)
	}
	// Retained seqs are {4,5}; minSeq=4. An edge at cursor 1 needs seq 2 (trimmed) → gap.
	res := s.Since(1, allowAll)
	assert.True(t, res.FlushRequired)
	assert.EqualValues(t, 5, res.MaxSeq)
	assert.Empty(t, res.Entries)

	// An edge at cursor 4 is within the window → incremental, no flush.
	res = s.Since(4, allowAll)
	assert.False(t, res.FlushRequired)
	require.Len(t, res.Entries, 1)
	assert.EqualValues(t, 5, res.Entries[0].Seq)
}

func TestPurgeStore_CursorAheadOfJournalFlushes(t *testing.T) {
	// Simulates a CP restart / fresh replica: the in-memory journal seq is low (or
	// zero) while an edge polls with a cursor it persisted against the older journal.
	// Without the cursor-ahead check, post-reset seqs (1,2,3…) would be <= the edge
	// cursor and silently dropped — an under-invalidation. The CP must flush instead.
	s := NewPurgeStore(0)
	res := s.Since(500, allowAll)
	assert.True(t, res.FlushRequired, "cursor ahead of an empty journal must flush")
	assert.EqualValues(t, 0, res.MaxSeq)

	// After the restart the CP issues a few purges; the edge cursor is still ahead.
	for i := 0; i < 3; i++ {
		_, _ = s.Add(purgeScopeURL, "a.com", "/x")
	}
	res = s.Since(500, allowAll)
	assert.True(t, res.FlushRequired, "cursor still ahead of lastSeq=3 must flush")
	assert.EqualValues(t, 3, res.MaxSeq)

	// Once the edge has realigned (cursor <= lastSeq), it polls incrementally again.
	res = s.Since(2, allowAll)
	assert.False(t, res.FlushRequired)
	require.Len(t, res.Entries, 1)
	assert.EqualValues(t, 3, res.Entries[0].Seq)
}

func TestPurgeStore_MaxUint64SinceFlushesNotPanics(t *testing.T) {
	s := NewPurgeStore(0)
	_, _ = s.Add(purgeScopeURL, "a.com", "/x")
	res := s.Since(^uint64(0), allowAll) // would overflow since+1; cursor-ahead catches it first
	assert.True(t, res.FlushRequired)
}

func TestPurgeStore_PrefixTrimsWhitespaceAndStores(t *testing.T) {
	s := NewPurgeStore(0)
	// Surrounding whitespace is trimmed; a rooted path is accepted and stored clean
	// (else the edge's normalizePrefix, which only trims a trailing slash, would keep
	// the spaces and the prefix would silently match nothing).
	_, ok := s.Add(purgeScopePrefix, "a.com", "  /blog  ")
	require.True(t, ok)
	res := s.Since(0, allowAll)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, "/blog", res.Entries[0].URI, "prefix trimmed to a clean rooted path")
}

func TestPurgeStore_PrefixScopedByHost(t *testing.T) {
	s := NewPurgeStore(0)
	_, ok := s.Add(purgeScopePrefix, "a.com", "/blog")
	require.True(t, ok)
	_, ok = s.Add(purgeScopePrefix, "other.com", "/x")
	require.True(t, ok)

	// An edge allowed only a.com gets a.com's prefix purge, never other.com's.
	res := s.Since(0, func(h string) bool { return h == "a.com" })
	require.Len(t, res.Entries, 1)
	assert.Equal(t, purgeScopePrefix, res.Entries[0].Scope)
	assert.Equal(t, "a.com", res.Entries[0].Host)
	assert.Equal(t, "/blog", res.Entries[0].URI)
}

func TestPurgeStore_InvalidInputsRejected(t *testing.T) {
	s := NewPurgeStore(0)
	cases := []struct{ scope, host, uri string }{
		{"bogus", "a.com", "/x"},
		{purgeScopeHost, "", ""},            // host scope needs a host
		{purgeScopeURL, "a.com", ""},        // url scope needs a uri
		{purgeScopeURL, "", "/x"},           // url scope needs a host
		{purgeScopeURL, "a.com", "blog"},    // url uri must be a rooted "/..." path
		{purgeScopePrefix, "a.com", ""},     // prefix scope needs a prefix path
		{purgeScopePrefix, "", "/x"},        // prefix scope needs a host
		{purgeScopePrefix, "a.com", "blog"}, // prefix must be a rooted "/..." path (typo guard)
	}
	for _, c := range cases {
		_, ok := s.Add(c.scope, c.host, c.uri)
		assert.False(t, ok, "scope=%q host=%q uri=%q should be rejected", c.scope, c.host, c.uri)
	}
	// Nothing was journaled.
	assert.EqualValues(t, 0, s.Since(0, allowAll).MaxSeq)
}

func TestPurgeStore_HostNormalized(t *testing.T) {
	s := NewPurgeStore(0)
	_, ok := s.Add(purgeScopeHost, "  ACME.com:443 ", "")
	require.True(t, ok)
	res := s.Since(0, allowAll)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, "acme.com", res.Entries[0].Host, "host lowercased, port-stripped, trimmed")
}
