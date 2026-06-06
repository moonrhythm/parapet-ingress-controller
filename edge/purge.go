package edge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/moonrhythm/parapet/pkg/cache"
)

// Scope is a purge's breadth.
type Scope string

const (
	// ScopeFlushAll invalidates everything cached at the apply instant.
	ScopeFlushAll Scope = "flush-all"
	// ScopeHost invalidates every URL under one host.
	ScopeHost Scope = "host"
	// ScopeURL invalidates one URL (all methods, schemes, and Vary variants).
	ScopeURL Scope = "url"
	// ScopePrefix invalidates every URL under a path prefix on a host (path-only,
	// boundary-aware; query strings ignored). The prefix travels in the URI field.
	ScopePrefix Scope = "prefix"
)

// PurgeEntry is one journal record as distributed by the control plane and applied
// by the edge. Seq is the monotonic journal sequence (idempotency cursor); Host is
// required for host/url/prefix scopes; URI carries the exact path+query for url
// scope and the path prefix for prefix scope. It is also the JSON wire shape
// returned by GET /v1/purges.
type PurgeEntry struct {
	Seq   uint64 `json:"seq"`
	Scope Scope  `json:"scope"`
	Host  string `json:"host,omitempty"`
	URI   string `json:"uri,omitempty"`
}

// PurgeTable is the edge's cache-invalidation state: a small, in-memory table of
// "everything cached at or before epoch T is invalid", consulted at cache-lookup
// time via InvalidatedAfter (the parapet/pkg/cache Options.InvalidatedAfter hook).
//
// It implements LAZY epoch invalidation: issuing a purge is O(1) (one map write
// stamping the edge's own wall clock), and an invalidated entry is physically
// reaped only on its NEXT lookup — exactly when the hook reports it stale, like a
// passed FreshUntil. Correctness is immediate (a purged entry can never be
// served); the storage backend's LRU byte cap reclaims disk regardless.
//
// Scopes, checked as a max at lookup so a URL is also covered by its host's purge,
// a matching path prefix, and a global flush:
//   - global  — flush-all (one epoch)
//   - host    — every URL under a host (keyed by normalized host)
//   - url     — one URL across all methods, schemes, and Vary variants (keyed by
//     hash(host ⊕ uri), so a single purge of /a covers GET+HEAD, http+https, and
//     every cached variant)
//   - prefix  — every URL under a path prefix on a host (path-only, boundary-aware:
//     /blog matches /blog and /blog/x but not /blogger; query strings ignored).
//     A linear scan of the host's prefix records, so it is O(prefixes-for-host) at
//     lookup rather than O(1); the record count is bounded by the cap-fold.
//
// The table persists {global, host, url, prefix, cursor} to a single file with an
// atomic temp+fsync+rename, so maps and cursor can never desync. It is safe for
// concurrent use.
type PurgeTable struct {
	mu     sync.RWMutex
	global int64                  // flush-all epoch (unix nanos); 0 = never flushed
	host   map[string]int64       // normalized host    -> epoch
	url    map[string]int64       // hash(host ⊕ uri)   -> epoch
	prefix map[string][]prefixRec // normalized host    -> path-prefix records
	cursor uint64                 // last journal seq applied (idempotency)

	// highWater is the largest epoch ever stamped. Every new stamp is clamped to be
	// >= highWater so a wall-clock step back (NTP correction) can never lower an
	// epoch and "un-purge" entries — purges are monotonic non-decreasing.
	highWater int64

	// folds counts conservative cap-folds (a map exceeded maxRecords and was folded
	// into the global epoch). Surfaced via Stats for metrics.
	folds uint64

	path     string       // persistence file; "" disables persistence (e.g. memory backend)
	maxRecs  int          // per-map record cap before a conservative fold-to-global
	nowNanos func() int64 // injectable clock (unix nanos); nil => time.Now
}

// prefixRec is one path-prefix purge for a host: the normalized prefix (trailing
// slash trimmed; "" means the whole host, i.e. a "/" purge) and its epoch. Exported
// fields so it round-trips through the persisted JSON.
type prefixRec struct {
	Prefix string `json:"prefix"`
	Epoch  int64  `json:"epoch"`
}

// defaultMaxPurgeRecords bounds each of the host/url maps. Purge records are
// created by operator-issued purges (not per request), so this is generous; on
// overflow the map folds into the global epoch (conservative over-invalidation,
// never under-invalidation), keeping memory finite without a reaper.
const defaultMaxPurgeRecords = 1 << 16

// NewPurgeTable builds the table, loading any persisted state from path. A path of
// "" disables persistence (the table lives only in memory). maxRecords <= 0 uses
// defaultMaxPurgeRecords. A missing state file is a clean first start (cursor 0); a
// corrupt/unreadable one resets to an empty table (cursor 0) so the next poll
// gaps and the control plane returns flush_required — conservative, never a silent
// under-invalidation. The load outcome is returned for logging; the table is
// always usable.
func NewPurgeTable(path string, maxRecords int) (*PurgeTable, error) {
	if maxRecords <= 0 {
		maxRecords = defaultMaxPurgeRecords
	}
	t := &PurgeTable{
		host:    map[string]int64{},
		url:     map[string]int64{},
		prefix:  map[string][]prefixRec{},
		path:    path,
		maxRecs: maxRecords,
	}
	err := t.load()
	return t, err
}

// now returns the current unix-nano clock (injectable for tests).
func (t *PurgeTable) now() int64 {
	if t.nowNanos != nil {
		return t.nowNanos()
	}
	return time.Now().UnixNano()
}

// InvalidatedAfter is the parapet/pkg/cache Options.InvalidatedAfter hook. It
// returns the invalidation epoch (unix nanos) applying to r: the max of the
// global, per-host, and per-url epochs. The cache treats a hit whose Meta.Created
// is <= this value as stale. Host normalization mirrors cache.primaryHash
// (lowercase + strip port) so the keys line up exactly. The stored Meta is unused.
func (t *PurgeTable) InvalidatedAfter(r *http.Request, _ cache.Meta) int64 {
	return t.epochFor(normHost(r.Host), r.URL.RequestURI())
}

// InvalidatedAfterMeta is the reaper's variant of InvalidatedAfter: it reads the
// (already-normalized) host + uri from a stored entry's Meta instead of a live
// request, so a sweep can match entries off the serving path. normHost is
// idempotent on Meta.Host (the cache stamps it normalized); an old entry with an
// empty Host matches only the global scope.
func (t *PurgeTable) InvalidatedAfterMeta(m cache.Meta) int64 {
	return t.epochFor(normHost(m.Host), m.URI)
}

// epochFor returns the invalidation epoch (unix nanos) applying to a normalized
// host + uri: the max of the global, per-host, and per-url epochs. Shared by the
// lookup hook and the reaper.
func (t *PurgeTable) epochFor(host, uri string) int64 {
	uk := urlKey(host, uri)
	path := pathOf(uri)
	t.mu.RLock()
	defer t.mu.RUnlock()
	e := t.global
	if v := t.host[host]; v > e {
		e = v
	}
	if v := t.url[uk]; v > e {
		e = v
	}
	// Prefix scope: linear scan of this host's prefix records (epoch check first so
	// the string match is skipped once a higher epoch is already found).
	for _, p := range t.prefix[host] {
		if p.Epoch > e && matchPrefix(path, p.Prefix) {
			e = p.Epoch
		}
	}
	return e
}

// Apply applies a batch of journal entries (only those with Seq > the pre-batch
// cursor, so re-delivered entries are idempotent), advances the cursor to maxSeq
// (covering empty batches and gaps within the retained range), and atomically
// persists the new state. Entry order is irrelevant — epochs clamp monotonically
// and the cursor is set from maxSeq. A persist failure is returned for logging but
// the in-memory state is already updated (and is the source of truth for serving);
// the next successful persist catches up, and a crash before then just re-polls
// from the durable cursor and re-applies idempotently.
func (t *PurgeTable) Apply(entries []PurgeEntry, maxSeq uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	base := t.cursor
	changed := false
	for _, e := range entries {
		if e.Seq <= base {
			continue // already applied in an earlier poll
		}
		t.applyLocked(e)
		changed = true
	}
	if maxSeq > t.cursor {
		t.cursor = maxSeq
		changed = true
	}
	// Persist only on a real change, so an idle poll (no new entries, cursor
	// unchanged) doesn't fsync — and the fsync-under-lock cost is paid only when an
	// actual purge advances the state, not on every poll tick.
	if !changed {
		return nil
	}
	return t.saveLocked()
}

// FlushAll bumps the global epoch (lazy flush-all), clears the host/url maps (now
// redundant — global supersedes any record <= it), sets the cursor to maxSeq, and
// persists. Used on the control plane's flush_required signal — both a cursor gap
// (maxSeq >= cursor: advance) and a journal reset where the CP's seq fell below the
// edge's cursor (maxSeq < cursor: realign DOWN). The cursor is set unconditionally
// (the one place a regression is safe: the flush just invalidated everything, so
// re-fetching from the new, lower maxSeq is idempotent) — otherwise a reset would
// leave the cursor stuck above the CP's journal and re-flush on every poll forever.
func (t *PurgeTable) FlushAll(maxSeq uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.global = t.stamp()
	t.host = map[string]int64{}
	t.url = map[string]int64{}
	t.prefix = map[string][]prefixRec{}
	t.cursor = maxSeq
	return t.saveLocked()
}

// applyLocked applies one entry's effect. Caller holds t.mu.
func (t *PurgeTable) applyLocked(e PurgeEntry) {
	switch e.Scope {
	case ScopeFlushAll:
		t.global = t.stamp()
		// global at >= every existing record makes them redundant; drop to reclaim memory.
		t.host = map[string]int64{}
		t.url = map[string]int64{}
		t.prefix = map[string][]prefixRec{}
	case ScopeHost:
		if h := normHost(e.Host); h != "" {
			t.host[h] = t.stamp()
			t.enforceCapLocked()
		}
	case ScopeURL:
		if h := normHost(e.Host); h != "" {
			t.url[urlKey(h, e.URI)] = t.stamp()
			t.enforceCapLocked()
		}
	case ScopePrefix:
		if h := normHost(e.Host); h != "" {
			t.applyPrefixLocked(h, normalizePrefix(e.URI), t.stamp())
			t.enforceCapLocked()
		}
	}
}

// applyPrefixLocked stamps (or refreshes) a host's path-prefix record. A repeat of
// the same prefix updates its epoch in place (monotonic, so always upward); a new
// prefix is appended. Caller holds t.mu.
func (t *PurgeTable) applyPrefixLocked(host, prefix string, epoch int64) {
	recs := t.prefix[host]
	for i := range recs {
		if recs[i].Prefix == prefix {
			if epoch > recs[i].Epoch {
				recs[i].Epoch = epoch
			}
			return
		}
	}
	t.prefix[host] = append(recs, prefixRec{Prefix: prefix, Epoch: epoch})
}

// stamp returns a fresh epoch, clamped to be monotonic non-decreasing (>=
// highWater) so a wall-clock step back can't un-purge. Caller holds t.mu.
func (t *PurgeTable) stamp() int64 {
	n := t.now()
	if n < t.highWater {
		n = t.highWater
	}
	t.highWater = n
	return n
}

// enforceCapLocked keeps each map within maxRecs by folding an overflowing map
// into the global epoch: global jumps to highWater (covering every record purged
// so far) and the map is cleared. This over-invalidates (a coarser flush) but
// NEVER under-invalidates, and bounds memory without a background reaper. Caller
// holds t.mu.
func (t *PurgeTable) enforceCapLocked() {
	folded := false
	if len(t.url) > t.maxRecs {
		t.url = map[string]int64{}
		folded = true
	}
	if len(t.host) > t.maxRecs {
		t.host = map[string]int64{}
		folded = true
	}
	if t.prefixCount() > t.maxRecs {
		t.prefix = map[string][]prefixRec{}
		folded = true
	}
	if folded {
		t.global = t.highWater // highWater >= every epoch stamped, so it covers the dropped records
		t.folds++
	}
}

// prefixCount totals the prefix records across hosts. Caller holds t.mu.
func (t *PurgeTable) prefixCount() int {
	n := 0
	for _, recs := range t.prefix {
		n += len(recs)
	}
	return n
}

// Cursor returns the last journal seq applied (for building the poll request).
func (t *PurgeTable) Cursor() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.cursor
}

// PurgeStats is a snapshot of the table for metrics/diagnostics.
type PurgeStats struct {
	Cursor     uint64
	Global     int64
	HostRecs   int
	URLRecs    int
	PrefixRecs int
	Folds      uint64
}

// Stats returns a concurrent-safe snapshot.
func (t *PurgeTable) Stats() PurgeStats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return PurgeStats{
		Cursor:     t.cursor,
		Global:     t.global,
		HostRecs:   len(t.host),
		URLRecs:    len(t.url),
		PrefixRecs: t.prefixCount(),
		Folds:      t.folds,
	}
}

// --- persistence ---

// persistState is the on-disk shape. Maps + cursor share one atomic write so they
// can never desync.
type persistState struct {
	Global int64                  `json:"global"`
	Host   map[string]int64       `json:"host"`
	URL    map[string]int64       `json:"url"`
	Prefix map[string][]prefixRec `json:"prefix,omitempty"`
	Cursor uint64                 `json:"cursor"`
}

// load reads persisted state into the table. A missing file is a clean start. Any
// other error (unreadable / corrupt JSON) leaves the table empty (cursor 0) and is
// returned for logging — the next poll gaps and the CP responds flush_required.
func (t *PurgeTable) load() error {
	if t.path == "" {
		return nil
	}
	data, err := os.ReadFile(t.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st persistState
	if err := json.Unmarshal(data, &st); err != nil {
		return err // table stays empty; conservative re-sync on next poll
	}
	if st.Host != nil {
		t.host = st.Host
	}
	if st.URL != nil {
		t.url = st.URL
	}
	if st.Prefix != nil {
		t.prefix = st.Prefix
	}
	t.global = st.Global
	t.cursor = st.Cursor
	t.highWater = st.Global
	for _, v := range t.host {
		if v > t.highWater {
			t.highWater = v
		}
	}
	for _, v := range t.url {
		if v > t.highWater {
			t.highWater = v
		}
	}
	for _, recs := range t.prefix {
		for _, p := range recs {
			if p.Epoch > t.highWater {
				t.highWater = p.Epoch
			}
		}
	}
	return nil
}

// saveLocked atomically persists the current state. Caller holds t.mu. A "" path
// is a no-op (persistence disabled).
func (t *PurgeTable) saveLocked() error {
	if t.path == "" {
		return nil
	}
	data, err := json.Marshal(persistState{
		Global: t.global,
		Host:   t.host,
		URL:    t.url,
		Prefix: t.prefix,
		Cursor: t.cursor,
	})
	if err != nil {
		return err
	}
	return atomicWriteFile(t.path, data)
}

// atomicWriteFile writes data to path via a same-dir temp file with
// write+fsync+close+rename, so a reader never sees a partial state file (matches
// the disk cache's commit idiom).
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".purge-state-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// --- keys ---

// normHost lowercases and strips the port from a host, mirroring
// cache.primaryHash exactly so a purge key matches the cache's stored key. It does
// NOT strip a trailing dot (neither does the cache).
func normHost(host string) string {
	h := strings.ToLower(host)
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return h
}

// urlKey is the per-url map key: hash(host ⊕ uri). uri is the request-uri
// (path+query). Hashing host⊕uri (not method/scheme) makes one url purge cover
// GET+HEAD, http+https, and every Vary variant at once.
func urlKey(host, uri string) string {
	sum := sha256.Sum256([]byte(host + "\n" + uri))
	return hex.EncodeToString(sum[:16])
}

// pathOf returns the path portion of a request-uri (everything before the first
// '?'). Prefix purges match on the path only, so a query string never affects
// whether an entry is covered.
func pathOf(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i]
	}
	return uri
}

// normalizePrefix trims a single trailing slash so "/blog" and "/blog/" purge the
// same section; "/" normalizes to "" (the whole-host prefix). The normalized form
// is what matchPrefix compares against.
func normalizePrefix(p string) string {
	return strings.TrimRight(p, "/")
}

// matchPrefix reports whether path is covered by the normalized prefix pre, on a
// path boundary: pre "/blog" matches "/blog" and "/blog/x" but NOT "/blogger". An
// empty pre (from a "/" purge) matches every path.
func matchPrefix(path, pre string) bool {
	if pre == "" {
		return true
	}
	return path == pre || strings.HasPrefix(path, pre+"/")
}
