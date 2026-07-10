package wafevent

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedClock pins the buffer inside one minute window; advance() crosses
// windows explicitly.
type fixedClock struct{ t time.Time }

func (c *fixedClock) now() time.Time          { return c.t }
func (c *fixedClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newTestBuffer(capacity int) (*Buffer, *fixedClock) {
	b := NewBuffer(capacity)
	c := &fixedClock{t: time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)}
	b.now = c.now
	return b, c
}

func logEvent(zone, rule string) Event {
	return Event{Zone: zone, RuleID: rule, Action: "log", ClientIP: "203.0.113.7", Method: "GET", Host: "example.com", Path: "/x"}
}

func blockEvent(zone, rule string) Event {
	return Event{Zone: zone, RuleID: rule, Action: "block", Status: 403, ClientIP: "203.0.113.7", Method: "POST", Host: "example.com", Path: "/wp-login.php"}
}

func TestRingCapOverwritesOldest(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(4)
	var drops []string
	b.OnDrop = func(zone string) { drops = append(drops, zone) }

	// 6 block events dodge the per-rule cap; zone cap (60) not reached.
	for range 6 {
		require.True(t, b.Append(blockEvent("ns/z", "r1"), nil))
	}

	events, next, _ := b.Read(b.boot, 0, 100)
	require.Len(t, events, 4, "ring keeps only the newest capacity events")
	assert.Equal(t, uint64(3), events[0].Seq, "oldest two were overwritten")
	assert.Equal(t, uint64(6), events[3].Seq)
	assert.Equal(t, uint64(6), next)
	assert.Equal(t, []string{"ns/z", "ns/z"}, drops, "each overwrite counts as a drop")
}

func TestPerRuleCap(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(128)
	drops := 0
	b.OnDrop = func(string) { drops++ }

	stored := 0
	for range 15 {
		if b.Append(logEvent("ns/z", "r1"), nil) {
			stored++
		}
	}
	assert.Equal(t, 10, stored, "per-(zone,rule) cap is 10/min")
	assert.Equal(t, 5, drops)

	// A different rule in the same zone has its own budget.
	assert.True(t, b.Append(logEvent("ns/z", "r2"), nil))
	// A different zone has its own budget for the same rule id.
	assert.True(t, b.Append(logEvent("ns/other", "r1"), nil))
}

func TestBlocksExemptFromRuleCapButNotZoneCap(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(128)
	drops := 0
	b.OnDrop = func(string) { drops++ }

	stored := 0
	for range 70 {
		if b.Append(blockEvent("ns/z", "r1"), nil) {
			stored++
		}
	}
	assert.Equal(t, 60, stored, "blocks bypass the 10/min rule cap but stop at the 60/min zone ceiling")
	assert.Equal(t, 10, drops)

	// The zone is saturated: even a block for another rule is rejected...
	assert.False(t, b.Append(blockEvent("ns/z", "r2"), nil))
	// ...but another zone is unaffected.
	assert.True(t, b.Append(blockEvent("ns/other", "r1"), nil))
}

func TestBlocksCountTowardZoneCapAlongsideLogs(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(128)
	// 55 blocks + 10 logs (rule cap admits all 10): zone ceiling admits 60 total.
	stored := 0
	for range 55 {
		if b.Append(blockEvent("ns/z", "rb"), nil) {
			stored++
		}
	}
	for range 10 {
		if b.Append(logEvent("ns/z", "rl"), nil) {
			stored++
		}
	}
	assert.Equal(t, 60, stored)
}

func TestWindowReset(t *testing.T) {
	t.Parallel()

	b, clock := newTestBuffer(128)
	for range 10 {
		require.True(t, b.Append(logEvent("ns/z", "r1"), nil))
	}
	require.False(t, b.Append(logEvent("ns/z", "r1"), nil), "cap reached in this window")

	clock.advance(time.Minute)
	assert.True(t, b.Append(logEvent("ns/z", "r1"), nil), "a new minute window resets the caps")
}

func TestCapRejectionSkipsEnrichAndMint(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(128)
	enriched := 0
	enrich := func(e *Event) {
		enriched++
		e.Country = "TH"
		e.ASN = 4750
	}
	for i := range 15 {
		stored := b.Append(logEvent("ns/z", "r1"), enrich)
		assert.Equal(t, i < 10, stored)
	}
	assert.Equal(t, 10, enriched, "enrich runs only for admitted events")

	events, _, _ := b.Read(b.boot, 0, 100)
	require.Len(t, events, 10)
	for _, e := range events {
		assert.Len(t, e.ID, 26, "admitted events carry a minted ULID")
		assert.Equal(t, "TH", e.Country)
		assert.Equal(t, int64(4750), e.ASN)
		assert.NotZero(t, e.At)
	}
}

func TestTruncation(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(8)
	e := logEvent("ns/z", "r1")
	e.Host = strings.Repeat("h", 300)
	e.Path = strings.Repeat("p", 300)
	require.True(t, b.Append(e, nil))

	events, _, _ := b.Read(b.boot, 0, 1)
	require.Len(t, events, 1)
	assert.Len(t, events[0].Host, 255)
	assert.Len(t, events[0].Path, 200)
}

func TestReadCursorPagination(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(128)
	for range 10 {
		require.True(t, b.Append(blockEvent("ns/z", "r1"), nil))
	}

	events, next, boot := b.Read(b.boot, 0, 3)
	require.Len(t, events, 3)
	assert.Equal(t, uint64(3), next)
	assert.Equal(t, b.boot, boot)

	events, next, _ = b.Read(boot, next, 3)
	require.Len(t, events, 3)
	assert.Equal(t, uint64(4), events[0].Seq)
	assert.Equal(t, uint64(6), next)

	events, next, _ = b.Read(boot, 6, 100)
	require.Len(t, events, 4)
	assert.Equal(t, uint64(10), next)

	// Exhausted: no events, cursor echoes back.
	events, next, _ = b.Read(boot, 10, 100)
	assert.Empty(t, events)
	assert.Equal(t, uint64(10), next)
}

func TestReadBootMismatchReplaysFromTail(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(4)
	for range 6 {
		require.True(t, b.Append(blockEvent("ns/z", "r1"), nil))
	}

	// A cursor from a previous process (different boot) restarts from the
	// oldest retained event, as does an after older than the ring tail.
	events, next, _ := b.Read("stale-boot", 5, 100)
	require.Len(t, events, 4)
	assert.Equal(t, uint64(3), events[0].Seq)
	assert.Equal(t, uint64(6), next)

	events, _, _ = b.Read(b.boot, 1, 100)
	require.Len(t, events, 4, "after below the retained tail replays from the tail")
	assert.Equal(t, uint64(3), events[0].Seq)

	// A future cursor (same boot — can't happen, but must not panic or hang)
	// also replays from the tail.
	events, _, _ = b.Read(b.boot, 99, 100)
	require.Len(t, events, 4)
}

func TestReadEmptyBuffer(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(8)
	events, next, boot := b.Read("", 0, 100)
	assert.Empty(t, events)
	assert.Zero(t, next)
	assert.Len(t, boot, 16, "boot id is 16 hex chars")
}

func TestULIDEncoding(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "00000000000000000000000000", encodeULID([16]byte{}))

	var max [16]byte
	for i := range max {
		max[i] = 0xFF
	}
	assert.Equal(t, "7ZZZZZZZZZZZZZZZZZZZZZZZZZ", encodeULID(max))

	// ms=1, random=0: the 48-bit timestamp occupies chars 0..9.
	var one [16]byte
	one[5] = 1
	assert.Equal(t, "00000000010000000000000000", encodeULID(one))
}

func TestULIDTimeOrdered(t *testing.T) {
	t.Parallel()

	t1 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Millisecond)
	id1 := mintULID(t1)
	id2 := mintULID(t2)
	require.Len(t, id1, 26)
	assert.Less(t, id1, id2, "ULIDs sort by timestamp")
	for _, c := range id1 + id2 {
		assert.Contains(t, crockford, string(c))
	}
	assert.NotEqual(t, mintULID(t1), mintULID(t1), "random component differs per mint")
}
