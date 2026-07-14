package wafevent

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

	events, next := b.Read(0, 100)
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

	events, _ := b.Read(0, 100)
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

	events, _ := b.Read(0, 1)
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

	events, next := b.Read(0, 3)
	require.Len(t, events, 3)
	assert.Equal(t, uint64(3), next)

	events, next = b.Read(next, 3)
	require.Len(t, events, 3)
	assert.Equal(t, uint64(4), events[0].Seq)
	assert.Equal(t, uint64(6), next)

	events, next = b.Read(6, 100)
	require.Len(t, events, 4)
	assert.Equal(t, uint64(10), next)

	// Exhausted: no events, cursor echoes back.
	events, next = b.Read(10, 100)
	assert.Empty(t, events)
	assert.Equal(t, uint64(10), next)
}

func TestReadClampsToRetainedTail(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(4)
	for range 6 {
		require.True(t, b.Append(blockEvent("ns/z", "r1"), nil))
	}

	// An after older than the ring tail (drop-oldest eviction outran the
	// flusher) resumes from the oldest retained event.
	events, next := b.Read(1, 100)
	require.Len(t, events, 4, "after below the retained tail resumes from the tail")
	assert.Equal(t, uint64(3), events[0].Seq)
	assert.Equal(t, uint64(6), next)

	// A future cursor (can't happen in-process, but must not panic or hang)
	// also resumes from the tail.
	events, _ = b.Read(99, 100)
	require.Len(t, events, 4)
}

func TestReadEmptyBuffer(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuffer(8)
	events, next := b.Read(0, 100)
	assert.Empty(t, events)
	assert.Zero(t, next)
}

// TestConcurrentAppendRead hammers the one mutex-guarded structure every
// request goroutine shares: writers append across zones while a reader pages
// with the echoed cursor, and the small ring forces constant eviction under
// the reads. The clock advances one minute per Append so the sampling caps
// never bind and every append is admitted. Meaningful under -race.
func TestConcurrentAppendRead(t *testing.T) {
	t.Parallel()

	const capacity = 64
	b := NewBuffer(capacity)
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	var tick atomic.Int64 // b.now runs under b.mu, but writers race to lock it
	b.now = func() time.Time { return base.Add(time.Duration(tick.Add(1)) * time.Minute) }
	var drops atomic.Int64
	b.OnDrop = func(string) { drops.Add(1) }

	const writers = 8
	const perWriter = 500

	var wg sync.WaitGroup
	var stored atomic.Int64
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			zone := "ns/z" + strconv.Itoa(w)
			for i := range perWriter {
				if b.Append(blockEvent(zone, "r"+strconv.Itoa(i%3)), nil) {
					stored.Add(1)
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	// The reader must never see a duplicate or rewound seq — even when
	// eviction outruns it and Read resumes from the ring tail — and every
	// ULID must be unique.
	seenIDs := make(map[string]bool)
	var last uint64
	after := uint64(0)
	for drained := false; !drained; {
		events, next := b.Read(after, 50)
		after = next
		for _, e := range events {
			require.Greater(t, e.Seq, last, "seqs must be strictly increasing across pages")
			last = e.Seq
			require.False(t, seenIDs[e.ID], "duplicate ULID %s", e.ID)
			seenIDs[e.ID] = true
			require.Len(t, e.ID, 26)
			require.NotEmpty(t, e.Zone)
		}
		if len(events) == 0 {
			select {
			case <-done:
				drained = true
			default:
			}
		}
	}

	// Every append landed in a fresh minute, so all were admitted; the only
	// drops are ring evictions, one per admit past capacity.
	require.EqualValues(t, writers*perWriter, stored.Load())
	assert.EqualValues(t, stored.Load(), b.seq, "seq counts exactly the admitted events")
	assert.EqualValues(t, stored.Load(), after, "reader drained through the final seq")
	assert.EqualValues(t, stored.Load()-capacity, drops.Load())
}

// TestSaturatedAppendDoesNotAllocate pins the Buffer doc claim for the
// flood path: past the caps, Append is mutex + map reads — no ULID mint, no
// enrich call, no allocation. The enrich closure captures a local (like the
// controller's OnMatch capturing the request) to prove the call site itself
// stays allocation-free too. AllocsPerRun reads the global malloc counter,
// so this test must not run in parallel with others.
func TestSaturatedAppendDoesNotAllocate(t *testing.T) {
	b, _ := newTestBuffer(128)
	for range maxPerZonePerMinute {
		require.True(t, b.Append(blockEvent("ns/z", "r1"), nil))
	}

	e := blockEvent("ns/z", "r1")
	allocs := testing.AllocsPerRun(100, func() {
		ip := e.ClientIP
		if b.Append(e, func(out *Event) { out.ClientIP = ip }) {
			t.Fatal("zone must stay saturated")
		}
	})
	assert.Zero(t, allocs)
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
