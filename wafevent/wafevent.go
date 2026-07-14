// Package wafevent keeps a bounded, sampled in-memory ring of zone WAF match
// events and pushes them from a per-pod background flusher directly to the
// deploys-app apiserver's collector.setWAFEvents RPC. It is the engine half of
// SPEC-waf-events: counters (parapet_waf_matches) remain the source of truth
// for counts; these are forensic samples, never a full request log. The ring
// is a send buffer — the only consumer is the in-process Flusher, which drains
// events past its high-water mark; nothing here listens on the network.
package wafevent

import (
	"encoding/binary"
	mrand "math/rand/v2"
	"sync"
	"time"
)

// DefaultCapacity is the ring size used by the controller: 8192 events is a
// few MiB worst-case, larger than one push batch (maxBatch) and over two
// hours of a single zone at its 60/min sampling cap — enough slack to ride
// out an ingest outage before drop-oldest eviction engages.
const DefaultCapacity = 8192

// Sampling caps, applied per minute-aligned window. The buffer is per
// controller pod, so both caps are per (zone, pod): a zone's real ceiling is
// the cap × N controller pods. The numbers are sized for "recognize the
// pattern", not for counting — 10 samples of one rule in a minute shows the
// repeated IP/path/country; the exact count lives in the metrics.
const (
	maxPerRulePerMinute = 10 // per (zone, ruleID); block events are exempt
	maxPerZonePerMinute = 60 // hard per-zone ceiling; blocks count too
)

const (
	maxHostBytes = 255
	maxPathBytes = 200
)

// Event is one sampled WAF match (SPEC-waf-events §C.1). The Flusher maps it
// to the collector.setWAFEvents wire item (see flusher.go); Zone and Seq stay
// ring-local and never go on the wire.
type Event struct {
	ID       string // ULID, minted at append (time-ordered, global dedupe key)
	Seq      uint64 // pod-local monotonic seq; the flusher's high-water mark counts these
	At       int64  // unix seconds
	Zone     string // registry key <namespace>/<configmap>
	RuleID   string // full project-prefixed id (<projectID>-<rand>)
	Action   string // log|allow|block
	Status   int    // configured block status (403 default)
	ClientIP string
	Country  string // ISO 3166-1 alpha-2, "" if unresolved
	ASN      int64  // 0 if unresolved
	Method   string
	Host     string // truncated to 255 bytes
	Path     string // URL.Path only (no query), truncated to 200 bytes
}

type ruleKey struct {
	zone string
	rule string
}

// Buffer is a bounded, sampled ring of zone WAF match events. Append runs
// synchronously on the request path (parapet invokes OnMatch inline in the
// request-serving goroutine), so the honest bound is not "never blocks" but
// "O(1), mutex-guarded, allocation-light, I/O-free": the sampling-cap check
// short-circuits FIRST, so during a saturated flood the per-match cost is one
// mutex hit + two map reads — no ULID mint, no GeoIP lookup, no allocation.
type Buffer struct {
	// OnDrop, when set, is called with the zone key of every event dropped by
	// the sampling caps or evicted by ring overwrite (the controller wires it
	// to the parapet_waf_event_drops metric). Set before the first Append; it
	// runs under the buffer lock and must be cheap.
	OnDrop func(zone string)

	mu  sync.Mutex
	buf []Event // ring: seqs inside are contiguous, oldest at start
	start,
	size int
	seq uint64 // last assigned; increments only for admitted (stored) events

	window    int64 // unix minute the counters below cover
	zoneCount map[string]int
	ruleCount map[ruleKey]int

	now func() time.Time // test hook
}

// NewBuffer returns an empty ring holding at most capacity events.
func NewBuffer(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Buffer{
		buf:       make([]Event, capacity),
		zoneCount: map[string]int{},
		ruleCount: map[ruleKey]int{},
		now:       time.Now,
	}
}

// Append applies the sampling caps and returns immediately when the window is
// saturated; only admitted events get the ULID mint and the enrich callback
// (the WAF hook resolves country/ASN there), keeping the rejected path free of
// GeoIP work. Reported drops (OnDrop) cover both cap rejections and the ring
// eviction a full buffer performs to admit e.
func (b *Buffer) Append(e Event, enrich func(*Event)) (stored bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if w := now.Unix() / 60; w != b.window {
		b.window = w
		clear(b.zoneCount)
		clear(b.ruleCount)
	}

	if b.zoneCount[e.Zone] >= maxPerZonePerMinute {
		b.drop(e.Zone)
		return false
	}
	// Blocks bypass the per-rule cap (they're what users came to see) but were
	// still subject to — and counted by — the zone ceiling above.
	if e.Action != "block" {
		k := ruleKey{zone: e.Zone, rule: e.RuleID}
		if b.ruleCount[k] >= maxPerRulePerMinute {
			b.drop(e.Zone)
			return false
		}
		b.ruleCount[k]++
	}
	b.zoneCount[e.Zone]++

	// Admitted: identity + enrichment are paid only past the caps.
	b.seq++
	e.Seq = b.seq
	e.At = now.Unix()
	e.ID = mintULID(now)
	e.Host = truncate(e.Host, maxHostBytes)
	e.Path = truncate(e.Path, maxPathBytes)

	var slot *Event
	if b.size == len(b.buf) {
		// Full: evict the oldest to admit the new event (newest wins — the
		// flusher lagging a whole ring means it will resume from here anyway).
		b.drop(b.buf[b.start].Zone)
		slot = &b.buf[b.start]
		b.start = (b.start + 1) % len(b.buf)
	} else {
		slot = &b.buf[(b.start+b.size)%len(b.buf)]
		b.size++
	}
	*slot = e
	// Enrich the ring slot, not e: handing &e to an unknown func would move
	// the whole Event copy to the heap on every call — including the
	// cap-rejected flood path the doc comment promises is allocation-free.
	if enrich != nil {
		enrich(slot)
	}
	return true
}

func (b *Buffer) drop(zone string) {
	if b.OnDrop != nil {
		b.OnDrop(zone)
	}
}

// Read returns up to max events with Seq > after, oldest first, plus the
// cursor to pass as after next time (the flusher's high-water mark). An after
// older than the ring's tail — drop-oldest eviction outran the flusher —
// resumes from the oldest retained event; duplicates on the wire are possible
// and harmless (the ingest dedupes on the ULID ID). Ring, mark, and process
// restart together, so there is no cross-process cursor to reconcile.
func (b *Buffer) Read(after uint64, max int) (events []Event, next uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if after > b.seq {
		// A cursor from the future can't be served; restart from the tail.
		after = 0
	}
	from := after + 1
	if oldest := b.seq - uint64(b.size) + 1; b.size > 0 && from < oldest {
		from = oldest
	}
	next = after
	if b.size == 0 || from > b.seq {
		return nil, next
	}
	n := b.seq - from + 1
	if max > 0 && uint64(max) < n {
		n = uint64(max)
	}
	events = make([]Event, n)
	oldest := b.seq - uint64(b.size) + 1
	for i := range events {
		events[i] = b.buf[(b.start+int(from-oldest)+i)%len(b.buf)]
	}
	next = from + n - 1
	return events, next
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// crockford is the ULID base32 alphabet (no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// mintULID returns a 26-char ULID: 48-bit unix-ms timestamp + 80 random bits,
// Crockford base32. Randomness comes from math/rand/v2's process-seeded
// generator — no syscall on the request path — which is plenty for a
// uniqueness (dedupe) key: these ids are not security tokens.
func mintULID(t time.Time) string {
	var id [16]byte
	ms := uint64(t.UnixMilli())
	id[0] = byte(ms >> 40)
	id[1] = byte(ms >> 32)
	id[2] = byte(ms >> 24)
	id[3] = byte(ms >> 16)
	id[4] = byte(ms >> 8)
	id[5] = byte(ms)
	binary.BigEndian.PutUint64(id[6:14], mrand.Uint64())
	binary.BigEndian.PutUint16(id[14:16], uint16(mrand.Uint64()))
	return encodeULID(id)
}

// encodeULID renders the 128-bit id as 26 base32 chars: the value is
// left-padded with 2 zero bits to 130 bits and emitted MSB-first in 5-bit
// groups, the standard ULID text encoding (lexicographic order == numeric
// order, so ids sort by timestamp).
func encodeULID(id [16]byte) string {
	var dst [26]byte
	for i := range dst {
		var v byte
		for j := range 5 {
			bit := 5*i + j // position in the 130-bit space
			v <<= 1
			if bit >= 2 { // first 2 bits are the zero pad
				k := bit - 2 // MSB-first index into the 128-bit id
				if id[k/8]&(1<<(7-k%8)) != 0 {
					v |= 1
				}
			}
		}
		dst[i] = crockford[v]
	}
	return string(dst[:])
}
