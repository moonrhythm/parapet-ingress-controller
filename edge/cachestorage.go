package edge

// cachestorage.go — parapet_cache_storage_* and parapet_cache_disk_* gauges.
//
// WHY THIS EXISTS
//
// Cache-outcome counters (parapet_cache_total / parapet_cache_egress_bytes) tell
// operators hit ratios and billing volume, but not whether the edge is about to
// thrash under its LRU byte cap or run the volume out of free space. These gauges
// close that gap:
//
//   - parapet_cache_storage_bytes{edge_id}       body bytes currently held by the
//     cache backend's LRU (eviction weight via Size() — not filesystem overhead
//     from .meta sidecars / shard dirs).
//   - parapet_cache_storage_max_bytes{edge_id}   configured body-byte cap
//     (MaxSize() / EDGE_CACHE_MAX_SIZE; fill ratio = storage / max).
//   - parapet_cache_disk_size_bytes{edge_id}     total size of the filesystem that
//     holds EDGE_CACHE_DIR (disk backend only).
//   - parapet_cache_disk_available_bytes{edge_id} free bytes available to an
//     unprivileged process on that filesystem (statfs Bavail; disk backend only).
//
// Disk series are omitted (not zeroed) when the backend is memory or when
// statfs fails, so a zero never looks like "disk is full".
//
// Collection is pull-based (prometheus.Collector): values are sampled on scrape,
// not on the request path. Storage size is O(1) via DiskStorage/MemoryStorage
// Size() — never Storage.Range (that would readdir+read every .meta on every
// scrape/push gather, competing with the cache volume).

import (
	"sync"

	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	descCacheStorageBytes = prometheus.NewDesc(
		prometheus.BuildFQName(prom.Namespace, "", "cache_storage_bytes"),
		"Body bytes currently held by the edge response cache (LRU eviction weight).",
		[]string{"edge_id"}, nil,
	)
	descCacheStorageMaxBytes = prometheus.NewDesc(
		prometheus.BuildFQName(prom.Namespace, "", "cache_storage_max_bytes"),
		"Configured body-byte cap of the edge response cache (EDGE_CACHE_MAX_SIZE).",
		[]string{"edge_id"}, nil,
	)
	descCacheDiskSizeBytes = prometheus.NewDesc(
		prometheus.BuildFQName(prom.Namespace, "", "cache_disk_size_bytes"),
		"Total size of the filesystem holding the edge response-cache directory.",
		[]string{"edge_id"}, nil,
	)
	descCacheDiskAvailableBytes = prometheus.NewDesc(
		prometheus.BuildFQName(prom.Namespace, "", "cache_disk_available_bytes"),
		"Free bytes available to an unprivileged process on the filesystem holding the edge response-cache directory.",
		[]string{"edge_id"}, nil,
	)

	cacheStorageOnce sync.Once
)

// storageSizer is implemented by parapet DiskStorage and MemoryStorage (O(1)
// LRU total + configured cap). Not on cache.Storage so custom backends stay free
// of an observability obligation.
type storageSizer interface {
	Size() int64
	MaxSize() int64
}

// cacheStorageCollector samples cache capacity + (when dir is set) the cache
// volume's filesystem usage on each Prometheus scrape.
type cacheStorageCollector struct {
	storage cache.Storage
	maxSize int64
	dir     string // empty → memory backend; disk metrics are not emitted
}

// RegisterCacheStorageMetrics registers the cache storage / disk gauges on the
// shared parapet registry. Call once when the response cache is enabled.
//
// maxSize is EDGE_CACHE_MAX_SIZE (used when storage does not expose MaxSize).
// dir is EDGE_CACHE_DIR for the disk backend, or "" for memory (disk size/
// available series are then never emitted).
func RegisterCacheStorageMetrics(storage cache.Storage, maxSize int64, dir string) {
	if storage == nil {
		return
	}
	if z, ok := storage.(storageSizer); ok {
		maxSize = z.MaxSize()
	}
	cacheStorageOnce.Do(func() {
		prom.Registry().MustRegister(&cacheStorageCollector{
			storage: storage,
			maxSize: maxSize,
			dir:     dir,
		})
	})
}

func (c *cacheStorageCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descCacheStorageBytes
	ch <- descCacheStorageMaxBytes
	if c.dir != "" {
		ch <- descCacheDiskSizeBytes
		ch <- descCacheDiskAvailableBytes
	}
}

func (c *cacheStorageCollector) Collect(ch chan<- prometheus.Metric) {
	id := edgeID
	ch <- prometheus.MustNewConstMetric(descCacheStorageBytes, prometheus.GaugeValue, float64(storageBodyBytes(c.storage)), id)
	ch <- prometheus.MustNewConstMetric(descCacheStorageMaxBytes, prometheus.GaugeValue, float64(c.maxSize), id)
	if c.dir == "" {
		return
	}
	size, avail, ok := diskUsage(c.dir)
	if !ok {
		// Omit rather than report 0 — a zero available looks like a full volume.
		return
	}
	ch <- prometheus.MustNewConstMetric(descCacheDiskSizeBytes, prometheus.GaugeValue, float64(size), id)
	ch <- prometheus.MustNewConstMetric(descCacheDiskAvailableBytes, prometheus.GaugeValue, float64(avail), id)
}

// storageBodyBytes returns the current LRU body-byte total for s via Size().
// Custom Storage without Size reports 0 (never Range — O(n) disk I/O on scrape
// is unsafe on a multi-gigabyte cache volume).
func storageBodyBytes(s cache.Storage) int64 {
	if s == nil {
		return 0
	}
	if z, ok := s.(storageSizer); ok {
		return z.Size()
	}
	return 0
}
