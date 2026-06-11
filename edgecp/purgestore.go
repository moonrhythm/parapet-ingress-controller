package edgecp

import (
	"net"
	"strings"
	"sync"
)

// Purge scope values on the wire. These MUST match the edge's edge.Scope strings
// (the two packages share only this JSON contract, never code).
const (
	purgeScopeFlushAll = "flush-all"
	purgeScopeHost     = "host"
	purgeScopeURL      = "url"
	purgeScopePrefix   = "prefix"
	purgeScopeTag      = "tag"
)

// defaultPurgeJournalMax bounds the in-memory journal. Purges are operator-issued
// (not per request), so a few thousand retained entries covers any realistic poll
// lag; older entries are trimmed and an edge that fell behind the retained window
// gets a flush_required (lazy flush-all) on its next poll — conservative, never an
// under-invalidation.
const defaultPurgeJournalMax = 4096

// purgeRecord is one journal entry. host is normalized (lowercased, port-stripped);
// uri is the request-uri (path+query, or path prefix) verbatim from the operator;
// tag is a surrogate key (tag scope, host-independent).
type purgeRecord struct {
	seq   uint64
	scope string
	host  string
	uri   string
	tag   string
}

// PurgeEntryDTO is the JSON wire shape of one purge entry (matches edge.PurgeEntry).
type PurgeEntryDTO struct {
	Seq   uint64 `json:"seq"`
	Scope string `json:"scope"`
	Host  string `json:"host,omitempty"`
	URI   string `json:"uri,omitempty"`
	Tag   string `json:"tag,omitempty"`
}

// PurgeSince is the GET /v1/purges response: the entries an edge hasn't applied yet
// (scoped to its allowed hosts), the highest journal seq, and a flush_required flag
// set when the edge's cursor fell behind the retained window (a gap).
type PurgeSince struct {
	Entries       []PurgeEntryDTO `json:"entries"`
	MaxSeq        uint64          `json:"max_seq"`
	FlushRequired bool            `json:"flush_required"`
}

// PurgeStore is the control plane's bounded append-only purge journal. An admin
// appends purges via Add (monotonic seq); each edge polls Since(cursor) to converge
// on its own timer, exactly like cert/WAF distribution. There is no per-edge state
// here — the cursor lives on the edge — so it is replica-friendly only in the sense
// that a single CP instance owns the journal; multiple CP replicas would each keep
// an independent journal (acceptable: an edge polling a different replica that lacks
// a recent entry simply gets flush_required on the gap, which over-invalidates
// safely). It is safe for concurrent use.
type PurgeStore struct {
	mu      sync.Mutex
	entries []purgeRecord
	lastSeq uint64 // highest seq issued (0 = none yet)
	minSeq  uint64 // smallest retained seq (1 when empty)
	maxKeep int
}

// NewPurgeStore builds the journal. maxEntries <= 0 uses defaultPurgeJournalMax.
func NewPurgeStore(maxEntries int) *PurgeStore {
	if maxEntries <= 0 {
		maxEntries = defaultPurgeJournalMax
	}
	return &PurgeStore{minSeq: 1, maxKeep: maxEntries}
}

// LastSeq returns the highest issued seq (0 = none yet) — the /v1/events change
// signal for the purge journal.
func (s *PurgeStore) LastSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeq
}

// Add appends a purge and returns its seq. scope must be one of flush-all / host /
// url / prefix / tag. host is required (and normalized) for host/url/prefix; uri is
// required for url (the exact on-the-wire path+query) and prefix (the path prefix),
// and MUST start with "/" so it can match a request path (a request-uri always
// does) — a no-leading-slash value would silently match nothing; uri must be in the
// same percent-encoded form the request carries (the cache keys on the raw
// RequestURI). tag is required for tag scope (a surrogate key, host-independent). A
// bad scope/host/uri/tag returns (0, false) so the handler can 400.
func (s *PurgeStore) Add(scope, host, uri, tag string) (uint64, bool) {
	scope = strings.TrimSpace(scope)
	switch scope {
	case purgeScopeFlushAll:
		host, uri, tag = "", "", ""
	case purgeScopeHost:
		host = normHostCP(host)
		if host == "" {
			return 0, false
		}
		uri, tag = "", ""
	case purgeScopeURL, purgeScopePrefix:
		// url: uri is the exact path+query; prefix: uri is the path prefix. Both must
		// be a rooted path ("/..."), else they'd never match a real request path —
		// reject so a typo surfaces as a 400 instead of a silent no-op purge.
		host = normHostCP(host)
		uri = strings.TrimSpace(uri)
		if host == "" || !strings.HasPrefix(uri, "/") {
			return 0, false
		}
		tag = ""
	case purgeScopeTag:
		// tag is a surrogate key, host-independent — distributed to every edge, which
		// then matches it against each entry's own Cache-Tag set. NOTE: unlike
		// host/url/prefix (host-gated by Since's allow), tag names are broadcast
		// fleet-wide, so they are a SHARED, cross-tenant-visible namespace — operators
		// must not encode secrets in Cache-Tag values.
		tag = strings.TrimSpace(tag)
		if tag == "" {
			return 0, false
		}
		host, uri = "", ""
	default:
		return 0, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSeq++
	s.entries = append(s.entries, purgeRecord{seq: s.lastSeq, scope: scope, host: host, uri: uri, tag: tag})
	if len(s.entries) > s.maxKeep {
		// Trim oldest; re-slice into a fresh backing array so the dropped records
		// are reclaimed rather than pinned by the slice header.
		s.entries = append([]purgeRecord(nil), s.entries[len(s.entries)-s.maxKeep:]...)
	}
	s.minSeq = s.entries[0].seq
	purgeIssued.WithLabelValues(scope).Inc()
	purgeJournalSize.Set(float64(len(s.entries)))
	return s.lastSeq, true
}

// Since returns the purges an edge with cursor `since` hasn't applied: entries with
// seq > since, filtered to flush-all and tag (both host-independent, so they reach
// every edge) plus host/url/prefix entries whose host the edge may serve (per
// allow). FlushRequired is set when the edge's next-needed seq was already trimmed
// (since+1 < minSeq) — the edge then bumps its global epoch and jumps to MaxSeq.
func (s *PurgeStore) Since(since uint64, allow func(host string) bool) PurgeSince {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := PurgeSince{MaxSeq: s.lastSeq}
	// Cursor ahead of the journal (since > lastSeq): the edge has applied a seq this
	// CP never issued, which means the journal was reset under it — a CP restart or a
	// fresh/lagging replica (the store is in-memory, so seq restarts at 0). Without
	// this, the post-reset seqs (1,2,3…) would all be <= the edge's stale cursor and
	// silently skipped — an indefinite UNDER-invalidation. flush-all so the edge
	// re-syncs and realigns its cursor down to MaxSeq. (Also subsumes the since=MaxUint64
	// overflow case, since MaxUint64 > lastSeq.)
	if since > s.lastSeq {
		res.FlushRequired = true
		return res
	}
	// Gap below the retained window: the edge's next-needed seq (since+1) was trimmed.
	if since+1 < s.minSeq {
		res.FlushRequired = true
		return res
	}
	for _, e := range s.entries {
		if e.seq <= since {
			continue
		}
		// flush-all and tag are host-independent (every edge); host/url/prefix are
		// gated by the token's hosts.
		if e.scope != purgeScopeFlushAll && e.scope != purgeScopeTag && !allow(e.host) {
			continue
		}
		res.Entries = append(res.Entries, PurgeEntryDTO{Seq: e.seq, Scope: e.scope, Host: e.host, URI: e.uri, Tag: e.tag})
	}
	return res
}

// normHostCP lowercases and strips the port from a host, mirroring the edge's
// normHost (and cache.primaryHash) so a purge key matches the edge's stored key. It
// also trims surrounding whitespace from operator input.
func normHostCP(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return h
}
