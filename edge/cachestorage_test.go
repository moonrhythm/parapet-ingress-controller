package edge

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// putStorageEntry seeds one entry into a cache.Storage (same helper shape as
// purgereaper_test, kept local so this file stays independent).
func putStorageEntry(t *testing.T, s cache.Storage, key string, m cache.Meta, body []byte) {
	t.Helper()
	w, err := s.Writer(key)
	require.NoError(t, err)
	_, err = w.Write(body)
	require.NoError(t, err)
	m.Size = int64(len(body))
	require.NoError(t, w.Commit(m))
}

func TestStorageBodyBytesMemory(t *testing.T) {
	s := cache.NewMemory(1 << 20)
	putStorageEntry(t, s, "aa01deadbeef", cache.Meta{Host: "a.com", URI: "/x"}, []byte("hello"))
	putStorageEntry(t, s, "bb02deadbeef", cache.Meta{Host: "b.com", URI: "/y"}, []byte("world!!"))

	assert.EqualValues(t, 5+7, storageBodyBytes(s))
	assert.EqualValues(t, 1<<20, s.MaxSize())
}

func TestStorageBodyBytesNilAndNonSizer(t *testing.T) {
	assert.Zero(t, storageBodyBytes(nil))
	// Custom Storage without Size must not fall back to Range (O(n) scrape cost).
	assert.Zero(t, storageBodyBytes(noSizeStorage{}))
}

// noSizeStorage is a minimal Storage that deliberately lacks Size/MaxSize so
// storageBodyBytes reports 0 rather than walking Range.
type noSizeStorage struct{}

func (noSizeStorage) Get(string) (cache.Meta, []byte, bool) { return cache.Meta{}, nil, false }
func (noSizeStorage) Writer(string) (cache.EntryWriter, error) {
	return nil, errors.New("unused")
}
func (noSizeStorage) Delete(string) {}
func (noSizeStorage) Range(func(string, cache.Meta) bool) {
	panic("Range must not be called for storage metrics")
}

func TestCacheStorageCollectorMemory(t *testing.T) {
	s := cache.NewMemory(1 << 20)
	putStorageEntry(t, s, "aa01deadbeef", cache.Meta{Host: "a.com", URI: "/"}, []byte("12345"))

	old := edgeID
	edgeID = "edge-storage-test"
	t.Cleanup(func() { edgeID = old })

	c := &cacheStorageCollector{storage: s, maxSize: s.MaxSize(), dir: ""}
	// Memory backend: only the two storage gauges.
	assert.Equal(t, 2, testutil.CollectAndCount(c))

	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(c))
	mfs, err := reg.Gather()
	require.NoError(t, err)

	got := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			var id string
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "edge_id" {
					id = lp.GetValue()
				}
			}
			assert.Equal(t, "edge-storage-test", id)
			got[mf.GetName()] = m.GetGauge().GetValue()
		}
	}
	assert.Equal(t, 5.0, got["parapet_cache_storage_bytes"])
	assert.Equal(t, float64(1<<20), got["parapet_cache_storage_max_bytes"])
	_, hasDisk := got["parapet_cache_disk_size_bytes"]
	assert.False(t, hasDisk, "memory backend must not emit disk series")
}

func TestCacheStorageCollectorDisk(t *testing.T) {
	dir := t.TempDir()
	s, err := cache.NewDisk(dir, 1<<20)
	require.NoError(t, err)
	putStorageEntry(t, s, "aa01deadbeef", cache.Meta{Host: "a.com", URI: "/"}, []byte("xyz"))

	old := edgeID
	edgeID = "edge-disk-test"
	t.Cleanup(func() { edgeID = old })

	c := &cacheStorageCollector{storage: s, maxSize: s.MaxSize(), dir: dir}
	// Storage pair + disk pair.
	assert.Equal(t, 4, testutil.CollectAndCount(c))

	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(c))
	mfs, err := reg.Gather()
	require.NoError(t, err)

	got := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			got[mf.GetName()] = m.GetGauge().GetValue()
		}
	}
	assert.Equal(t, 3.0, got["parapet_cache_storage_bytes"])
	assert.Equal(t, float64(1<<20), got["parapet_cache_storage_max_bytes"])
	assert.Greater(t, got["parapet_cache_disk_size_bytes"], 0.0)
	// Available can be 0 on a truly full volume; on a temp dir it should be > 0.
	assert.Greater(t, got["parapet_cache_disk_available_bytes"], 0.0)
	// Available must not exceed total size.
	assert.LessOrEqual(t, got["parapet_cache_disk_available_bytes"], got["parapet_cache_disk_size_bytes"])
}

func TestDiskUsageMissingPath(t *testing.T) {
	_, _, ok := diskUsage(filepath.Join(t.TempDir(), "no-such-subdir-that-does-not-exist-xxx"))
	// Statfs on a missing path fails on unix — series would be omitted.
	// (Some platforms may succeed if the parent is readable; only require that
	// a clearly impossible path under / does not panic.)
	_ = ok
	_, _, ok = diskUsage(filepath.Join(string(os.PathSeparator), "no", "such", "path", "parapet-edge-test"))
	assert.False(t, ok, "statfs of a non-existent absolute path should fail")
}
