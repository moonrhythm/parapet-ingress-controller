package edge

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/stretchr/testify/assert"
)

// serveCacheStatus drives one request through the CacheStatus middleware with the
// given inner handler, returning the recorded response.
func serveCacheStatus(inner http.HandlerFunc) *httptest.ResponseRecorder {
	h := CacheStatus().ServeHandler(inner)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://x.example.com/", nil)
	h.ServeHTTP(rec, r)
	return rec
}

func TestCacheStatusStampsBypass(t *testing.T) {
	t.Parallel()

	t.Run("no X-Cache from inner -> BYPASS", func(t *testing.T) {
		rec := serveCacheStatus(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("origin"))
		})
		assert.Equal(t, "BYPASS", rec.Header().Get("X-Cache"))
		assert.Equal(t, "origin", rec.Body.String())
	})

	t.Run("write-only (implicit 200) -> BYPASS", func(t *testing.T) {
		rec := serveCacheStatus(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("body"))
		})
		assert.Equal(t, "BYPASS", rec.Header().Get("X-Cache"))
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("error status with no X-Cache -> BYPASS", func(t *testing.T) {
		rec := serveCacheStatus(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusBadGateway)
		})
		assert.Equal(t, "BYPASS", rec.Header().Get("X-Cache"))
		assert.Equal(t, http.StatusBadGateway, rec.Code)
	})
}

func TestCacheStatusPreservesManagedStatus(t *testing.T) {
	t.Parallel()

	// A cache-managed response sets X-Cache before WriteHeader; CacheStatus must
	// never overwrite it.
	for _, tag := range []string{"HIT", "MISS", "STALE"} {
		t.Run(tag+" preserved", func(t *testing.T) {
			rec := serveCacheStatus(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Cache", tag)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("x"))
			})
			assert.Equal(t, tag, rec.Header().Get("X-Cache"))
		})
	}

	t.Run("origin-set X-Cache preserved on bypass", func(t *testing.T) {
		rec := serveCacheStatus(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Cache", "HIT") // e.g. an origin with its own cache
			_, _ = w.Write([]byte("x"))
		})
		assert.Equal(t, "HIT", rec.Header().Get("X-Cache"))
	})
}

// TestCacheStatusWithRealCache wires CacheStatus around the actual
// parapet/pkg/cache to prove the integration: a real bypass yields BYPASS, while
// a real cache-managed MISS keeps its own X-Cache tag.
func TestCacheStatusWithRealCache(t *testing.T) {
	t.Parallel()

	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte("ok"))
	})
	c := cache.New(cache.NewMemory(1<<20), cache.Options{
		// /private is declared non-cacheable -> the cache bypasses it.
		Cacheable: func(r *http.Request) bool { return !strings.HasPrefix(r.URL.Path, "/private") },
		// Match the edge default so the chunked (no Content-Length) origin body is
		// storable and the second GET is a real HIT.
		CacheChunked: true,
	})
	h := CacheStatus().ServeHandler(c.ServeHandler(origin))

	do := func(method, path string) string {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "http://x.example.com"+path, nil))
		return rec.Header().Get("X-Cache")
	}

	// Cacheable GET: the cache contacts the origin and tags MISS — CacheStatus must
	// not overwrite it.
	assert.Equal(t, "MISS", do(http.MethodGet, "/public"))
	// Same URL again: served from store, HIT — also preserved.
	assert.Equal(t, "HIT", do(http.MethodGet, "/public"))
	// Cacheable=false -> real bypass -> stamped BYPASS.
	assert.Equal(t, "BYPASS", do(http.MethodGet, "/private/x"))
	// Non-cacheable method -> real bypass -> stamped BYPASS.
	assert.Equal(t, "BYPASS", do(http.MethodPost, "/public"))
}

// recordingWriter captures each WriteHeader code and the X-Cache header value
// present at that moment — httptest.ResponseRecorder can't model a 1xx interim
// followed by a final status (it freezes on the first WriteHeader).
type recordingWriter struct {
	header   http.Header
	codes    []int
	xcacheAt []string
}

func (w *recordingWriter) Header() http.Header { return w.header }
func (w *recordingWriter) WriteHeader(code int) {
	w.codes = append(w.codes, code)
	w.xcacheAt = append(w.xcacheAt, w.header.Get("X-Cache"))
}
func (w *recordingWriter) Write(b []byte) (int, error) { return len(b), nil }

func TestCacheStatus1xxNotTagged(t *testing.T) {
	t.Parallel()

	// A 1xx interim head must pass through untagged; the BYPASS tag belongs on the
	// final status. Verify the 103 is forwarded carrying no X-Cache, and the final
	// 200 is forwarded carrying BYPASS.
	rw := &recordingWriter{header: http.Header{}}
	h := CacheStatus().ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusEarlyHints) // 103 interim
		w.WriteHeader(http.StatusOK)         // final
		_, _ = w.Write([]byte("body"))
	}))
	h.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "http://x/", nil))

	assert.Equal(t, []int{http.StatusEarlyHints, http.StatusOK}, rw.codes, "both heads must be forwarded")
	assert.Equal(t, "", rw.xcacheAt[0], "the 103 interim must carry no X-Cache")
	assert.Equal(t, "BYPASS", rw.xcacheAt[1], "the final head must carry BYPASS")
	assert.Equal(t, "BYPASS", rw.header.Get("X-Cache"))
}

// hijackRecorder is an httptest.ResponseRecorder that also reports a Hijacker, so
// the interface-preservation test can assert CacheStatus forwards Hijack.
type hijackRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

func (h *hijackRecorder) Flush() {}

func TestCacheStatusPreservesInterfaces(t *testing.T) {
	t.Parallel()

	hr := &hijackRecorder{ResponseRecorder: httptest.NewRecorder()}
	var gotFlusher, gotHijacker bool
	h := CacheStatus().ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, gotFlusher = w.(http.Flusher)
		hj, ok := w.(http.Hijacker)
		gotHijacker = ok
		if ok {
			// a hijacked upgrade never calls WriteHeader -> stays untagged
			_, _, _ = hj.Hijack()
		}
	}))
	h.ServeHTTP(hr, httptest.NewRequest(http.MethodGet, "http://x/", nil))

	assert.True(t, gotFlusher, "Flusher must be exposed through the wrapper")
	assert.True(t, gotHijacker, "Hijacker must be exposed through the wrapper")
	assert.True(t, hr.hijacked, "Hijack must reach the underlying writer")
	assert.Empty(t, hr.Header().Get("X-Cache"), "a hijacked upgrade must not be tagged")
}
