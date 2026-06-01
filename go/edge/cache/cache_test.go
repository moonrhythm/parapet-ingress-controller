package cache

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// originSpec describes the response a fake origin returns.
type originSpec struct {
	body   []byte
	header http.Header
	status int
	sleep  time.Duration
}

func origin(spec originSpec, calls *int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		if spec.sleep > 0 {
			time.Sleep(spec.sleep)
		}
		for k, vs := range spec.header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		if w.Header().Get("Content-Length") == "" {
			w.Header().Set("Content-Length", strconv.Itoa(len(spec.body)))
		}
		st := spec.status
		if st == 0 {
			st = http.StatusOK
		}
		w.WriteHeader(st)
		_, _ = w.Write(spec.body)
	})
}

func newTestCache(t *testing.T) *Cache {
	t.Helper()
	c, err := New(Config{Dir: t.TempDir(), MaxSize: 1 << 20, MaxFileSize: 1024})
	require.NoError(t, err)
	return c
}

// do serves one request through the cache wrapping the origin, returning the
// recorder.
func do(c *Cache, h http.Handler, method, target string, reqHeader http.Header) *httptest.ResponseRecorder {
	mw := c.Middleware().ServeHandler(h)
	req := httptest.NewRequest(method, target, nil)
	for k, vs := range reqHeader {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	return rec
}

func TestCache_MissThenHit(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	h := origin(originSpec{body: []byte("hello"), header: hdr("Cache-Control", "max-age=60")}, &calls)

	r1 := do(c, h, "GET", "http://acme.com/a", nil)
	assert.Equal(t, "MISS", r1.Header().Get("X-Cache"))
	assert.Equal(t, "hello", r1.Body.String())

	r2 := do(c, h, "GET", "http://acme.com/a", nil)
	assert.Equal(t, "HIT", r2.Header().Get("X-Cache"))
	assert.Equal(t, "hello", r2.Body.String())

	assert.EqualValues(t, 1, atomic.LoadInt32(&calls), "origin contacted once")
}

func TestCache_NonCacheableAlwaysMiss(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	h := origin(originSpec{body: []byte("dyn")}, &calls) // no freshness directive

	do(c, h, "GET", "http://acme.com/d", nil)
	r := do(c, h, "GET", "http://acme.com/d", nil)
	assert.Equal(t, "MISS", r.Header().Get("X-Cache"))
	assert.EqualValues(t, 2, atomic.LoadInt32(&calls), "uncacheable -> origin every time")
}

func TestCache_IgnoresClientCacheControl(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	h := origin(originSpec{body: []byte("x"), header: hdr("Cache-Control", "max-age=60")}, &calls)
	do(c, h, "GET", "http://acme.com/a", nil)
	// Client no-cache must NOT bust the shared cache (CDN behavior).
	r := do(c, h, "GET", "http://acme.com/a", hdr("Cache-Control", "no-cache"))
	assert.Equal(t, "HIT", r.Header().Get("X-Cache"))
	assert.EqualValues(t, 1, atomic.LoadInt32(&calls))
}

func TestCache_VarySeparatesVariants(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	h := origin(originSpec{body: []byte("v"), header: hdr("Cache-Control", "max-age=60", "Vary", "Accept-Encoding")}, &calls)

	do(c, h, "GET", "http://acme.com/a", hdr("Accept-Encoding", "gzip")) // MISS (store gzip variant)
	gz := do(c, h, "GET", "http://acme.com/a", hdr("Accept-Encoding", "gzip"))
	assert.Equal(t, "HIT", gz.Header().Get("X-Cache"), "same variant hits")
	br := do(c, h, "GET", "http://acme.com/a", hdr("Accept-Encoding", "br"))
	assert.Equal(t, "MISS", br.Header().Get("X-Cache"), "different variant misses")
	assert.EqualValues(t, 2, atomic.LoadInt32(&calls), "one fetch per variant")
}

func TestCache_PerObjectCapNotCached(t *testing.T) {
	c := newTestCache(t) // MaxFileSize 1024
	var calls int32
	big := make([]byte, 2000)
	h := origin(originSpec{body: big, header: hdr("Cache-Control", "max-age=60")}, &calls)
	do(c, h, "GET", "http://acme.com/big", nil)
	r := do(c, h, "GET", "http://acme.com/big", nil)
	assert.Equal(t, "MISS", r.Header().Get("X-Cache"), "over-cap object not cached")
	assert.EqualValues(t, 2, atomic.LoadInt32(&calls))
}

func TestCache_HeadAndPostBehavior(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	h := origin(originSpec{body: []byte("body"), header: hdr("Cache-Control", "max-age=60")}, &calls)
	// POST never engages the cache (no X-Cache header).
	r := do(c, h, "POST", "http://acme.com/a", nil)
	assert.Equal(t, "", r.Header().Get("X-Cache"))
}

func TestCache_ExpiredEntryIsMiss(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	h := origin(originSpec{body: []byte("e"), header: hdr("Cache-Control", "max-age=60")}, &calls)

	// Populate, then force the stored entry stale by rewriting its meta with a
	// past FreshUntil (same atomic write path the cache uses).
	req := httptest.NewRequest("GET", "http://acme.com/exp", nil)
	do(c, h, "GET", "http://acme.com/exp", nil)
	primary := c.primaryHash(req)
	variant := c.variantHash(primary, req)
	m, body, ok := c.store.read(variant)
	require.True(t, ok)
	m.FreshUntil = time.Now().Add(-time.Minute).UnixNano()
	tmp, err := c.store.newTemp(variant)
	require.NoError(t, err)
	_, _ = tmp.Write(body)
	require.NoError(t, c.store.commit(variant, m, tmp))

	r := do(c, h, "GET", "http://acme.com/exp", nil)
	assert.Equal(t, "MISS", r.Header().Get("X-Cache"), "expired entry is a miss")
	assert.EqualValues(t, 2, atomic.LoadInt32(&calls))
}

func TestCache_SingleFlightCollapsesConcurrentMisses(t *testing.T) {
	c := newTestCache(t)
	var calls int32
	h := origin(originSpec{body: []byte("slow"), header: hdr("Cache-Control", "max-age=60"), sleep: 60 * time.Millisecond}, &calls)
	mw := c.Middleware().ServeHandler(h)

	const n = 12
	var wg sync.WaitGroup
	var miss, hit int32
	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start.Wait() // fire all at once
			req := httptest.NewRequest("GET", "http://acme.com/s", nil)
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)
			assert.Equal(t, "slow", rec.Body.String())
			switch rec.Header().Get("X-Cache") {
			case "MISS":
				atomic.AddInt32(&miss, 1)
			case "HIT":
				atomic.AddInt32(&hit, 1)
			}
		}()
	}
	start.Done()
	wg.Wait()

	assert.EqualValues(t, 1, atomic.LoadInt32(&calls), "concurrent misses collapse into one origin fetch")
	assert.EqualValues(t, 1, atomic.LoadInt32(&miss), "exactly one MISS (the leader)")
	assert.EqualValues(t, n-1, atomic.LoadInt32(&hit), "followers served from the just-filled cache")
}

func TestCache_SingleFlightCollapsesConcurrentVaryFirstFill(t *testing.T) {
	// Regression: on a COLD cache the lookup/lock key uses an empty Vary, but the
	// leader stores under the response's Vary key. Concurrent followers (same
	// varied value) must still collapse to one origin fetch — they re-key with the
	// just-learned Vary after the leader finishes.
	c := newTestCache(t)
	var calls int32
	h := origin(originSpec{
		body:   []byte("varybody"),
		header: hdr("Cache-Control", "max-age=60", "Vary", "Accept-Encoding"),
		sleep:  60 * time.Millisecond,
	}, &calls)
	mw := c.Middleware().ServeHandler(h)

	const n = 12
	var wg, start sync.WaitGroup
	var miss, hit int32
	start.Add(1)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start.Wait()
			req := httptest.NewRequest("GET", "http://acme.com/v", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)
			assert.Equal(t, "varybody", rec.Body.String())
			switch rec.Header().Get("X-Cache") {
			case "MISS":
				atomic.AddInt32(&miss, 1)
			case "HIT":
				atomic.AddInt32(&hit, 1)
			}
		}()
	}
	start.Done()
	wg.Wait()

	assert.EqualValues(t, 1, atomic.LoadInt32(&calls), "concurrent first-fill of a Vary'd URL collapses to one origin fetch")
	assert.EqualValues(t, 1, atomic.LoadInt32(&miss))
	assert.EqualValues(t, n-1, atomic.LoadInt32(&hit))
}

func TestCache_LeaderPanicLeavesNoTempLeak(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, MaxSize: 1 << 20, MaxFileSize: 1024})
	require.NoError(t, err)

	// An upstream that panics after starting a cacheable response. The deferred
	// cleanup must discard the in-progress temp file (no FD/file leak).
	panicky := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("partial"))
		panic("upstream blew up mid-response")
	})
	mw := c.Middleware().ServeHandler(panicky)

	func() {
		defer func() { _ = recover() }() // swallow the propagated panic
		mw.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://acme.com/boom", nil))
	}()

	ents, err := os.ReadDir(filepath.Join(dir, "tmp"))
	require.NoError(t, err)
	assert.Empty(t, ents, "panic during fill must not leak a temp file")

	// And the cache is still usable afterwards.
	var calls int32
	ok := origin(originSpec{body: []byte("ok"), header: hdr("Cache-Control", "max-age=60")}, &calls)
	r := do(c, ok, "GET", "http://acme.com/after", nil)
	assert.Equal(t, "MISS", r.Header().Get("X-Cache"))
}

func TestCache_FarFutureFreshnessStillHits(t *testing.T) {
	// A max-age that would push fresh-until past time.UnixNano's range (~2262) is
	// clamped, so the entry is cacheable and actually serves a hit (regression:
	// it used to be stored then reaped on the first lookup due to the wrap).
	c := newTestCache(t)
	var calls int32
	h := origin(originSpec{body: []byte("immortal"), header: hdr("Cache-Control", "max-age=7445000000")}, &calls) // ~236 years
	r1 := do(c, h, "GET", "http://acme.com/far", nil)
	assert.Equal(t, "MISS", r1.Header().Get("X-Cache"))
	r2 := do(c, h, "GET", "http://acme.com/far", nil)
	assert.Equal(t, "HIT", r2.Header().Get("X-Cache"), "clamped far-future TTL still serves a hit")
	assert.EqualValues(t, 1, atomic.LoadInt32(&calls))
}

func TestCache_RestartPersistence(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, MaxSize: 1 << 20, MaxFileSize: 1024}

	a, err := New(cfg)
	require.NoError(t, err)
	var callsA int32
	ha := origin(originSpec{body: []byte("persist"), header: hdr("Cache-Control", "max-age=600")}, &callsA)
	do(a, ha, "GET", "http://acme.com/p", nil) // store on disk

	// "Restart": a fresh cache over the same dir serves the entry from disk (a
	// no-Vary entry is reachable immediately; the byte cap re-seeds via the scan).
	b, err := New(cfg)
	require.NoError(t, err)
	var callsB int32
	hb := origin(originSpec{body: []byte("persist"), header: hdr("Cache-Control", "max-age=600")}, &callsB)
	r := do(b, hb, "GET", "http://acme.com/p", nil)
	assert.Equal(t, "HIT", r.Header().Get("X-Cache"), "survived restart")
	assert.EqualValues(t, 0, atomic.LoadInt32(&callsB), "served from disk, origin not contacted")

	assert.Eventually(t, func() bool { return b.evict.size() > 0 }, time.Second, 10*time.Millisecond,
		"startup scan re-seeds the LRU byte accounting")
}
