package geoip

import "sync"

// cacheCap bounds each result cache to at most this many distinct client IPs.
//
// GeoIP results are tiny (a 2-byte country string or an int64 ASN keyed by an
// IP string), so 16384 entries is only on the order of ~1 MB per cache yet large
// enough to absorb the working set of distinct client IPs a single proxy sees in
// the lifetime of one cache generation. When a cache fills past the cap it is
// cleared wholesale (see resultCache.get); the cap is the knob that trades worst-
// case memory for how often that cold-start clear happens. 16384 keeps memory
// trivially small while making a full clear a rare event under realistic traffic.
const cacheCap = 16384

// resultCache is a tiny, bounded, concurrency-safe memo from a client-IP string
// to a GeoIP lookup result of type V (a country string or an int64 ASN). It is
// deliberately not a true LRU: GeoIP results are stable and cheap, so when the
// map grows past cacheCap we simply clear it in place and start a fresh
// generation. That keeps the hot path a single map read under an RWMutex with no
// per-entry bookkeeping, and bounds memory at roughly cacheCap entries.
//
// Negative results (an unplaceable IP -> "XX" or 0) are cached too: that matches
// the underlying lookup's semantics exactly (it always returns a value, never an
// error to the caller) and stops repeat unplaceable IPs from re-hitting the mmdb.
type resultCache[V any] struct {
	mu sync.RWMutex
	m  map[string]V
}

func newResultCache[V any]() *resultCache[V] {
	return &resultCache[V]{m: make(map[string]V)}
}

// get returns the memoized result for key, computing it via compute on a miss.
// compute is the existing uncached lookup; its output is stored verbatim, so the
// cache is fully transparent (same value for every key as calling compute would
// give). On a miss that would push the map past cacheCap, the map is cleared in
// place before inserting, bounding it at cacheCap+1 entries momentarily and then
// starting a fresh generation.
func (c *resultCache[V]) get(key string, compute func() V) V {
	c.mu.RLock()
	v, ok := c.m[key]
	c.mu.RUnlock()
	if ok {
		return v
	}

	// Compute outside the write lock: the lookup may touch the mmap, and two
	// goroutines racing the same cold key just both compute the same value.
	v = compute()

	c.mu.Lock()
	if len(c.m) >= cacheCap {
		// Bounded "clear when full": drop the whole generation rather than do
		// per-entry eviction. Cheap, and GeoIP results are cheap to recompute.
		// clear() empties in place and keeps the backing array (already sized for
		// cacheCap), so the next generation refills with no map regrowth/rehash;
		// the retained capacity is bounded by cacheCap, the memory cap we accept.
		clear(c.m)
	}
	c.m[key] = v
	c.mu.Unlock()
	return v
}

// len reports the current number of cached entries (test helper / introspection).
func (c *resultCache[V]) len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.m)
}
