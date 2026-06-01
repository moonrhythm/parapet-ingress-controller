package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/moonrhythm/parapet"
)

// cacheLockTimeout bounds how long a concurrent miss waits for the in-flight
// fill (the "leader") to populate the cache before fetching on its own. Matches
// the Rust edge's 2s CacheLock timeout.
const cacheLockTimeout = 2 * time.Second

// Config configures the disk cache. All from EDGE_CACHE_* env in main.
type Config struct {
	Dir         string
	MaxSize     int64 // total on-disk bytes cap (LRU-evicted)
	MaxFileSize int64 // per-object bytes cap
}

// Cache is the edge response cache. Construct with New; mount Middleware() into
// the chain wrapping the upstream forwarder.
type Cache struct {
	cfg   Config
	store *store
	evict *lru

	pvMu        sync.RWMutex
	primaryVary map[string][]string // primaryHex -> Vary header names learned from a stored response

	lockMu sync.Mutex
	locks  map[string]*fillLock // variantHex -> in-flight fill
}

// fillLock coordinates concurrent misses for one variant: the leader fills, the
// rest wait on done (then re-read the cache) or time out and fetch on their own.
type fillLock struct {
	done chan struct{}
}

// maxPrimaryVary bounds the in-memory primary->Vary map so a long-tail URL space
// can't grow it without limit (the disk LRU bounds bytes, not this map). When the
// cap is hit the map is reset; a dropped entry just costs one re-learn (the next
// fill re-records its Vary), so correctness is unaffected. Matches the
// clear-at-cap pattern in go/geoip's result cache.
const maxPrimaryVary = 1 << 16

// New opens (creating if needed) the cache dir and starts the background startup
// scan that re-seeds the LRU + Vary map and reaps orphans/expired entries off
// the serving path. Returns an error only if the dir can't be initialized.
func New(cfg Config) (*Cache, error) {
	st, err := newStore(cfg.Dir)
	if err != nil {
		return nil, err
	}
	c := &Cache{
		cfg:         cfg,
		store:       st,
		evict:       newLRU(cfg.MaxSize),
		primaryVary: map[string][]string{},
		locks:       map[string]*fillLock{},
	}
	go c.startupScan()
	return c, nil
}

// startupScan re-admits surviving entries to the LRU and re-learns their Vary
// names so the byte cap and Vary keying hold across restarts. Runs in the
// background; the edge serves immediately and the cap simply lags until done.
func (c *Cache) startupScan() {
	start := time.Now()
	entries := c.store.scan(start)
	for _, e := range entries {
		c.setPrimaryVary(e.meta.PrimaryHex, e.meta.Vary)
		for _, victim := range c.evict.admit(e.variant, e.meta.Size) {
			c.store.remove(victim)
		}
	}
	slog.Info("edge cache: startup scan complete",
		"seeded", len(entries), "bytes", c.evict.size(), "elapsed", time.Since(start))
}

// Middleware returns the cache middleware. It wraps the upstream forwarder
// (next): a hit short-circuits next; a miss fetches via next and stores.
func (c *Cache) Middleware() parapet.Middleware {
	return parapet.MiddlewareFunc(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.serve(w, r, next)
		})
	})
}

func (c *Cache) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if !cacheableMethod(r.Method) || isUpgrade(r) {
		next.ServeHTTP(w, r) // never cache these; no X-Cache header
		return
	}
	primaryHex := c.primaryHash(r)
	variantHex := c.variantHash(primaryHex, r)

	if c.tryServeHit(w, r, variantHex) {
		return
	}
	c.fillAndServe(w, r, next, primaryHex, variantHex)
}

// tryServeHit serves variantHex from disk if present and fresh, returning true.
// An expired entry is reaped and reported as a miss (fail-static on any IO
// problem — it just reads as a miss).
func (c *Cache) tryServeHit(w http.ResponseWriter, r *http.Request, variantHex string) bool {
	m, body, ok := c.store.read(variantHex)
	if !ok {
		return false
	}
	if time.Now().After(m.freshUntilTime()) {
		c.store.remove(variantHex)
		c.evict.remove(variantHex)
		return false
	}
	c.evict.touch(variantHex)
	writeStored(w, r, m, body, "HIT")
	return true
}

// fillAndServe handles a miss. The first arrival becomes the leader and fills the
// cache while streaming to its own client; concurrent arrivals wait for the
// leader (then read from cache) or time out and fetch on their own. Followers and
// the leader all tag X-Cache accurately (HIT when served from the just-filled
// cache, MISS when they contacted the origin).
func (c *Cache) fillAndServe(w http.ResponseWriter, r *http.Request, next http.Handler, primaryHex, variantHex string) {
	lock, leader := c.acquire(variantHex)
	if !leader {
		select {
		case <-lock.done:
		case <-time.After(cacheLockTimeout):
		}
		// The leader has finished (or we timed out). Recompute our variant key:
		// the leader may have just learned this primary's Vary, so our key now
		// matches the stored entry IF our varied-header values match the leader's
		// (otherwise we correctly miss and fetch our own variant — never serving a
		// wrong Vary variant). A miss here (uncacheable / different variant /
		// evicted / timeout) falls through to our own origin fetch, no store.
		if c.tryServeHit(w, r, c.variantHash(primaryHex, r)) {
			return
		}
		w.Header().Set("X-Cache", "MISS")
		next.ServeHTTP(w, r)
		return
	}

	defer c.release(variantHex, lock)
	tw := &teeWriter{rw: w, r: r, c: c, method: r.Method, primaryHex: primaryHex}
	defer tw.cleanup() // panic-safe: discard the temp body if finish never ran
	next.ServeHTTP(tw, r)
	tw.finish()
}

func (c *Cache) acquire(variantHex string) (*fillLock, bool) {
	c.lockMu.Lock()
	defer c.lockMu.Unlock()
	if l, ok := c.locks[variantHex]; ok {
		return l, false
	}
	l := &fillLock{done: make(chan struct{})}
	c.locks[variantHex] = l
	return l, true
}

func (c *Cache) release(variantHex string, l *fillLock) {
	c.lockMu.Lock()
	delete(c.locks, variantHex)
	c.lockMu.Unlock()
	close(l.done)
}

// primaryHash keys on host + method + scheme + uri (so distinct hosts/schemes/
// methods never collide). scheme reflects the terminating listener via
// X-Forwarded-Proto (set by the parapet server), defaulting to the request TLS
// state.
func (c *Cache) primaryHash(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	uri := r.URL.RequestURI()
	sum := sha256.Sum256([]byte(strings.ToLower(r.Host) + "\n" + r.Method + "\n" + scheme + "\n" + uri))
	return hex.EncodeToString(sum[:16])
}

// variantHash mixes the primary hash with the request's values for the Vary
// header names learned for this primary, so distinct Vary variants get distinct
// entries. Before the primary's Vary is known (first request / pre-scan) the
// variance is empty — so the very first fill stores under the actual response's
// Vary (see teeWriter.finish), which a later lookup then matches once the Vary
// map is learned.
func (c *Cache) variantHash(primaryHex string, r *http.Request) string {
	return variantHashFor(primaryHex, c.getPrimaryVary(primaryHex), r.Header)
}

// variantHashFor computes the on-disk variant key. names must be sorted +
// lowercased; the variance is each name's value in h. The same (primaryHex,
// names, h) on the lookup and store paths yields the same key.
func variantHashFor(primaryHex string, names []string, h http.Header) string {
	var b strings.Builder
	b.WriteString(primaryHex)
	b.WriteByte(0)
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(h.Get(name))
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:16])
}

func (c *Cache) getPrimaryVary(primaryHex string) []string {
	c.pvMu.RLock()
	defer c.pvMu.RUnlock()
	return c.primaryVary[primaryHex]
}

func (c *Cache) setPrimaryVary(primaryHex string, names []string) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	c.pvMu.Lock()
	// Bound the map: a dropped entry just re-learns on the next fill.
	if len(c.primaryVary) >= maxPrimaryVary {
		if _, exists := c.primaryVary[primaryHex]; !exists {
			c.primaryVary = make(map[string][]string, maxPrimaryVary)
		}
	}
	c.primaryVary[primaryHex] = sorted
	c.pvMu.Unlock()
}

// store admits a freshly-committed entry to the LRU, evicting as needed.
func (c *Cache) admit(variantHex string, size int64) {
	for _, victim := range c.evict.admit(variantHex, size) {
		c.store.remove(victim)
	}
}

// writeStored writes a cached entry to the client. body is omitted for HEAD and
// bodiless statuses. X-Cache is set to tag (HIT/MISS).
func writeStored(w http.ResponseWriter, r *http.Request, m *meta, body []byte, tag string) {
	h := w.Header()
	for k, vs := range m.Header {
		h[k] = append([]string(nil), vs...)
	}
	h.Set("X-Cache", tag)
	w.WriteHeader(m.Status)
	if r.Method == http.MethodHead || m.Status == http.StatusNoContent {
		return
	}
	_, _ = w.Write(body)
}
