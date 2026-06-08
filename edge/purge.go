package edge

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/moonrhythm/parapet/pkg/cache/purge"
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
	// ScopeTag invalidates every cached response carrying a surrogate key (from the
	// origin's Cache-Tag header), across all hosts. The tag travels in the Tag field.
	ScopeTag Scope = "tag"
)

// PurgeEntry is one journal record as distributed by the control plane and applied
// by the edge. Seq is the monotonic journal sequence (idempotency cursor); Host is
// required for host/url/prefix scopes; URI carries the exact path+query for url
// scope and the path prefix for prefix scope; Tag carries the surrogate key for tag
// scope (host-independent). It is also the JSON wire shape returned by GET /v1/purges.
type PurgeEntry struct {
	Seq   uint64 `json:"seq"`
	Scope Scope  `json:"scope"`
	Host  string `json:"host,omitempty"`
	URI   string `json:"uri,omitempty"`
	Tag   string `json:"tag,omitempty"`
}

// PurgeTable is the edge's cache-invalidation state. The invalidation mechanics —
// the lazy epoch table consulted via InvalidatedAfter, the per-host/url/prefix/tag
// scopes, the monotonic clamp, and the cap-fold memory bound — live in
// parapet's pkg/cache/purge. This type adds the control-plane DISTRIBUTION layer
// on top: the journal cursor (idempotency), Apply/FlushAll over journal records,
// and atomic persistence of {table snapshot, cursor} so the two can never desync.
//
// It is safe for concurrent use. The embedded purge.Table guards its own state;
// mu here guards the cursor and serializes the persistence orchestration.
type PurgeTable struct {
	tbl *purge.Table

	mu     sync.Mutex // guards cursor (+ dirtyVer)
	cursor uint64     // last journal seq applied (idempotency)

	// dirtyVer is bumped (under mu) for each persisted snapshot. persistMu serializes
	// the actual file write OFF the mu critical section — so the fsync never blocks a
	// serving-path InvalidatedAfter — while persistedVer (under persistMu) drops a
	// stale snapshot whose newer successor already landed.
	dirtyVer     uint64
	persistMu    sync.Mutex
	persistedVer uint64

	path string // persistence file; "" disables persistence (e.g. memory backend)
}

// NewPurgeTable builds the table, loading any persisted state from path. A path of
// "" disables persistence (the table lives only in memory). maxRecords <= 0 uses
// the package default. A missing state file is a clean first start (cursor 0); a
// corrupt/unreadable one resets to an empty table (cursor 0) so the next poll gaps
// and the control plane returns flush_required — conservative, never a silent
// under-invalidation. The load outcome is returned for logging; the table is always
// usable. Extra purge.Options (e.g. a test clock) are forwarded to the table.
func NewPurgeTable(path string, maxRecords int, opts ...purge.Option) (*PurgeTable, error) {
	t := &PurgeTable{
		tbl:  purge.New(append([]purge.Option{purge.WithMaxRecords(maxRecords)}, opts...)...),
		path: path,
	}
	return t, t.load()
}

// InvalidatedAfter is the parapet/pkg/cache Options.InvalidatedAfter hook.
func (t *PurgeTable) InvalidatedAfter(r *http.Request, m cache.Meta) int64 {
	return t.tbl.InvalidatedAfter(r, m)
}

// InvalidatedAfterMeta is the reaper's variant: it reads host+uri from a stored
// entry's Meta instead of a live request.
func (t *PurgeTable) InvalidatedAfterMeta(m cache.Meta) int64 {
	return t.tbl.InvalidatedAfterMeta(m)
}

// Reap physically deletes every entry the table has invalidated, returning the
// count. See ReapOnce / RunReaper for the scheduled wrapper.
func (t *PurgeTable) Reap(storage cache.Storage) int {
	return t.tbl.Reap(storage)
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
	base := t.cursor
	changed := false
	for _, e := range entries {
		if e.Seq <= base {
			continue // already applied in an earlier poll
		}
		t.applyOne(e)
		changed = true
	}
	if maxSeq > t.cursor {
		t.cursor = maxSeq
		changed = true
	}
	// Persist only on a real change, so an idle poll doesn't fsync.
	if !changed {
		t.mu.Unlock()
		return nil
	}
	snap, ver := t.snapshotLocked()
	t.mu.Unlock()
	return t.persist(snap, ver)
}

// applyOne dispatches one journal record to the table. The table normalizes hosts
// and stamps a monotonic epoch internally.
func (t *PurgeTable) applyOne(e PurgeEntry) {
	switch e.Scope {
	case ScopeFlushAll:
		t.tbl.FlushAll()
	case ScopeHost:
		t.tbl.PurgeHost(e.Host)
	case ScopeURL:
		t.tbl.PurgeURL(e.Host, e.URI)
	case ScopePrefix:
		t.tbl.PurgePrefix(e.Host, e.URI)
	case ScopeTag:
		t.tbl.PurgeTag(e.Tag)
	}
}

// FlushAll bumps the global epoch (lazy flush-all), sets the cursor to maxSeq, and
// persists. Used on the control plane's flush_required signal — both a cursor gap
// (maxSeq >= cursor: advance) and a journal reset where the CP's seq fell below the
// edge's cursor (maxSeq < cursor: realign DOWN). The cursor is set unconditionally
// (the one place a regression is safe: the flush just invalidated everything, so
// re-fetching from the new, lower maxSeq is idempotent) — otherwise a reset would
// leave the cursor stuck above the CP's journal and re-flush on every poll forever.
func (t *PurgeTable) FlushAll(maxSeq uint64) error {
	t.mu.Lock()
	t.tbl.FlushAll()
	t.cursor = maxSeq
	snap, ver := t.snapshotLocked()
	t.mu.Unlock()
	return t.persist(snap, ver)
}

// Cursor returns the last journal seq applied (for building the poll request).
func (t *PurgeTable) Cursor() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cursor
}

// PurgeStats is a snapshot of the table for metrics/diagnostics.
type PurgeStats struct {
	Cursor     uint64
	Global     int64
	HostRecs   int
	URLRecs    int
	PrefixRecs int
	TagRecs    int
	Folds      uint64
}

// Stats returns a concurrent-safe snapshot.
func (t *PurgeTable) Stats() PurgeStats {
	s := t.tbl.Stats()
	return PurgeStats{
		Cursor:     t.Cursor(),
		Global:     s.Global,
		HostRecs:   s.HostRecs,
		URLRecs:    s.URLRecs,
		PrefixRecs: s.PrefixRecs,
		TagRecs:    s.TagRecs,
		Folds:      s.Folds,
	}
}

// --- persistence ---

// persistState is the on-disk shape: the table's snapshot (host/url/prefix/tag/
// global, promoted to top-level keys by the embed) plus the cursor, in one atomic
// write so they can never desync. The layout matches the pre-migration format, so
// existing state files load without a flush.
type persistState struct {
	purge.Snapshot
	Cursor uint64 `json:"cursor"`
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
	t.tbl.Restore(st.Snapshot)
	t.cursor = st.Cursor
	return nil
}

// snapshotLocked captures the persistable state and a monotonic version, so the
// caller can fsync it OUTSIDE t.mu (see persist). Caller holds t.mu.
func (t *PurgeTable) snapshotLocked() (persistState, uint64) {
	t.dirtyVer++
	return persistState{Snapshot: t.tbl.Snapshot(), Cursor: t.cursor}, t.dirtyVer
}

// persist atomically writes a snapshot to disk WITHOUT holding t.mu. persistMu
// serializes writes and persistedVer drops a stale snapshot whose newer successor
// already landed, so an older Apply can never overwrite a newer one's on-disk
// state. A "" path is a no-op. A write error is returned for logging; the in-memory
// table is authoritative and the next change re-persists.
func (t *PurgeTable) persist(snap persistState, ver uint64) error {
	if t.path == "" {
		return nil
	}
	t.persistMu.Lock()
	defer t.persistMu.Unlock()
	if ver <= t.persistedVer {
		return nil // a newer snapshot already won the race to disk
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	if err := atomicWriteFile(t.path, data); err != nil {
		return err
	}
	t.persistedVer = ver
	return nil
}

// atomicWriteFile writes data to path via a same-dir temp file with
// write+fsync+close+rename, then fsyncs the parent directory so the rename itself
// is durable.
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
	return fsyncDir(dir)
}

// fsyncDir flushes a directory entry so a rename into it survives a crash.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
