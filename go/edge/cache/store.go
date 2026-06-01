package cache

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// reapMinAge gates orphan/torn-write reaping during the startup scan: a file is
// only deleted if its mtime is at least this old, so a concurrent in-flight
// commit (body renamed in, .meta not yet) is never touched. Matches the Rust
// edge's REAP_MIN_AGE_SECS.
const reapMinAge = 60 * time.Second

// meta is the JSON sidecar describing a cached variant. Written last (after the
// body), so the presence of a .meta implies a complete .body.
type meta struct {
	Status     int         `json:"status"`
	Header     http.Header `json:"header"`
	PrimaryHex string      `json:"primary"` // primary key hash (host+method+scheme+uri)
	Vary       []string    `json:"vary"`    // lowercased Vary header names
	Created    int64       `json:"created"` // unix nanos
	FreshUntil int64       `json:"fresh"`   // unix nanos; entry is stale after this
	Size       int64       `json:"size"`    // body bytes (== eviction weight)
}

func (m *meta) freshUntilTime() time.Time { return time.Unix(0, m.FreshUntil) }

// store is the on-disk backing for the cache, sharded by the first 2 hex chars
// of the variant hash:
//
//	<dir>/<aa>/<variant>.body   response body bytes
//	<dir>/<aa>/<variant>.meta   JSON sidecar (written last)
//	<dir>/tmp/<variant>.<seq>   in-progress writes, atomically renamed on commit
type store struct {
	dir string
	seq atomic.Uint64
}

func newStore(dir string) (*store, error) {
	if dir == "" {
		return nil, errors.New("cache: empty dir")
	}
	if err := os.MkdirAll(filepath.Join(dir, "tmp"), 0o755); err != nil {
		return nil, err
	}
	return &store{dir: dir}, nil
}

func (s *store) shardDir(variant string) string { return filepath.Join(s.dir, variant[:2]) }
func (s *store) bodyPath(variant string) string {
	return filepath.Join(s.shardDir(variant), variant+".body")
}
func (s *store) metaPath(variant string) string {
	return filepath.Join(s.shardDir(variant), variant+".meta")
}
func (s *store) tempPath(prefix string) string {
	n := s.seq.Add(1)
	return filepath.Join(s.dir, "tmp", prefix+"."+strconv.FormatUint(n, 10))
}

// newTemp opens a fresh temp file for streaming a body during a fill.
func (s *store) newTemp(variant string) (*os.File, error) {
	return os.Create(s.tempPath(variant))
}

// read loads a variant's meta + body. ok=false on any miss / corruption / torn
// write (fail-static — the caller treats it as a cache miss, never an error).
func (s *store) read(variant string) (*meta, []byte, bool) {
	mb, err := os.ReadFile(s.metaPath(variant))
	if err != nil {
		return nil, nil, false // clean miss or unreadable -> miss
	}
	var m meta
	if err := json.Unmarshal(mb, &m); err != nil {
		return nil, nil, false // corrupt sidecar -> miss
	}
	body, err := os.ReadFile(s.bodyPath(variant))
	if err != nil {
		return nil, nil, false // meta without body (torn) -> miss
	}
	return &m, body, true
}

// commit finalizes a fill: fsync the already-written temp body, atomically
// rename it to <variant>.body, then atomically write <variant>.meta LAST so its
// presence implies a complete body. On a meta-write failure the body is rolled
// back so no orphan remains. tmp is the open temp file (its contents already
// written by the caller); commit closes it.
func (s *store) commit(variant string, m *meta, tmp *os.File) error {
	tmpName := tmp.Name()
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.MkdirAll(s.shardDir(variant), 0o755); err != nil {
		os.Remove(tmpName)
		return err
	}
	body := s.bodyPath(variant)
	if err := os.Rename(tmpName, body); err != nil {
		os.Remove(tmpName)
		return err
	}
	mb, err := json.Marshal(m)
	if err != nil {
		os.Remove(body)
		return err
	}
	if err := atomicWrite(s.metaPath(variant), mb, s.tempPath(variant+".meta")); err != nil {
		os.Remove(body) // roll back the body so a body without meta isn't left
		return err
	}
	return nil
}

// remove deletes a variant's files (meta first, so a half-deleted entry reads as
// a clean miss rather than a torn write).
func (s *store) remove(variant string) {
	os.Remove(s.metaPath(variant))
	os.Remove(s.bodyPath(variant))
}

// scannedEntry is one surviving cache entry found by scan.
type scannedEntry struct {
	variant    string
	meta       *meta
	freshUntil time.Time
}

// scan walks the cache dir, reaping orphans / torn writes / expired entries
// (age-gated so in-flight commits are spared) and returning the survivors so the
// caller can re-seed the LRU + the host->vary map. Runs off the serving path.
func (s *store) scan(now time.Time) []scannedEntry {
	var out []scannedEntry

	// Reap stale temp files (abandoned in-progress writes).
	tmpDir := filepath.Join(s.dir, "tmp")
	if ents, err := os.ReadDir(tmpDir); err == nil {
		for _, e := range ents {
			p := filepath.Join(tmpDir, e.Name())
			reapIfStale(p, now)
		}
	}

	shards, err := os.ReadDir(s.dir)
	if err != nil {
		return out
	}
	for _, sh := range shards {
		if !sh.IsDir() || sh.Name() == "tmp" {
			continue
		}
		shardPath := filepath.Join(s.dir, sh.Name())
		ents, err := os.ReadDir(shardPath)
		if err != nil {
			continue
		}
		// Index which variants have a .body so we can detect orphan .meta / .body.
		bodies := map[string]struct{}{}
		var metas []string
		for _, e := range ents {
			name := e.Name()
			switch {
			case strings.HasSuffix(name, ".body"):
				bodies[strings.TrimSuffix(name, ".body")] = struct{}{}
			case strings.HasSuffix(name, ".meta"):
				metas = append(metas, strings.TrimSuffix(name, ".meta"))
			}
		}
		seenMeta := map[string]struct{}{}
		for _, variant := range metas {
			seenMeta[variant] = struct{}{}
			mp := filepath.Join(shardPath, variant+".meta")
			mb, err := os.ReadFile(mp)
			if err != nil {
				continue
			}
			var m meta
			if err := json.Unmarshal(mb, &m); err != nil {
				// corrupt sidecar -> reap meta + body (age-gated)
				reapIfStale(mp, now)
				reapIfStale(filepath.Join(shardPath, variant+".body"), now)
				continue
			}
			if _, hasBody := bodies[variant]; !hasBody {
				reapIfStale(mp, now) // meta without body (torn) -> reap
				continue
			}
			if now.After(m.freshUntilTime()) {
				// expired -> reap both
				os.Remove(mp)
				os.Remove(filepath.Join(shardPath, variant+".body"))
				continue
			}
			out = append(out, scannedEntry{variant: variant, meta: &m, freshUntil: m.freshUntilTime()})
		}
		// .body files with no matching .meta -> orphan (age-gated reap).
		for variant := range bodies {
			if _, ok := seenMeta[variant]; !ok {
				reapIfStale(filepath.Join(shardPath, variant+".body"), now)
			}
		}
	}
	return out
}

// reapIfStale deletes path only if its mtime is at least reapMinAge old, so a
// concurrent in-flight commit is never deleted.
func reapIfStale(path string, now time.Time) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	if now.Sub(fi.ModTime()) >= reapMinAge {
		os.Remove(path)
	}
}

// atomicWrite writes data to tmpPath, fsyncs it, then renames to path.
func atomicWrite(path string, data []byte, tmpPath string) error {
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
