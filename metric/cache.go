package metric

import "sync"

// cache is a concurrency-safe, lazily-populated map keyed by a comparable K.
// It memoizes per-label-set metric handles so the request hot path avoids
// re-resolving (and re-hashing) Prometheus labels on every call. Reads on the
// common already-cached path take only a shared RLock.
type cache[K comparable, V any] struct {
	mu sync.RWMutex
	m  map[K]V
}

func newCache[K comparable, V any](sizeHint int) *cache[K, V] {
	return &cache[K, V]{m: make(map[K]V, sizeHint)}
}

// getOrCreate returns the cached value for key, calling create to build and
// store it on the first miss. create runs at most once per key, while the write
// lock is held, so it must not call back into the same cache.
func (c *cache[K, V]) getOrCreate(key K, create func() V) V {
	c.mu.RLock()
	v, ok := c.m[key]
	c.mu.RUnlock()
	if ok {
		return v
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.m[key]; ok {
		return v
	}
	v = create()
	c.m[key] = v
	return v
}
