package edge

// cachestatus.go — stamp `X-Cache: BYPASS` on responses the cache won't manage.
//
// parapet/pkg/cache sets X-Cache to HIT / MISS / STALE for every response it
// manages, and ALWAYS sets it on the shared header map before it calls
// WriteHeader on the underlying writer (writeStored, the teeWriter fill path,
// and serveLeader all Set("X-Cache", …) then WriteHeader). A *bypass* — a
// non-cacheable method, a protocol upgrade, a Range request, or Options.Cacheable
// returning false — is proxied straight to the origin with no X-Cache header at
// all.
//
// So, observed from immediately OUTSIDE the cache, "no X-Cache present when the
// header block is about to flush" is exactly a bypass. CacheStatus wraps the
// writer and, on the first real (non-1xx) WriteHeader/Write, stamps
// `X-Cache: BYPASS` iff no X-Cache is already set. A managed response is never
// touched, and an X-Cache an origin set itself is preserved. Hijacked upgrades
// never reach WriteHeader, so a 101 stays untagged — consistent with CacheEgress.

import (
	"bufio"
	"net"
	"net/http"

	"github.com/moonrhythm/parapet"
)

// CacheStatus returns middleware that stamps `X-Cache: BYPASS` on responses the
// response cache declined to manage. Mount it immediately OUTSIDE (before) the
// cache so its writer wraps the cache's output and its WriteHeader fires after
// the cache has set any X-Cache of its own.
func CacheStatus() parapet.Middleware {
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(&cacheStatusRW{ResponseWriter: w}, r)
		})
	})
}

// cacheStatusRW wraps ResponseWriter and stamps X-Cache: BYPASS on the first
// non-1xx response head when no X-Cache is present. It preserves the optional
// interfaces the chain relies on: Flush (SSE/chunked), Hijack (WebSocket/upgrade),
// Push (HTTP/2), Unwrap.
type cacheStatusRW struct {
	http.ResponseWriter
	wroteHeader bool
}

// tagBypass runs once, immediately before the header block is flushed: if the
// cache (or origin) set no X-Cache, this response bypassed the cache.
func (w *cacheStatusRW) tagBypass() {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if w.Header().Get("X-Cache") == "" {
		w.Header().Set("X-Cache", "BYPASS")
	}
}

func (w *cacheStatusRW) WriteHeader(code int) {
	// 1xx interim responses (100 Continue, 103 Early Hints) are not the final
	// status and X-Cache belongs on the final head — pass them through untouched.
	if code >= 100 && code < 200 {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.tagBypass()
	w.ResponseWriter.WriteHeader(code)
}

func (w *cacheStatusRW) Write(p []byte) (int, error) {
	w.tagBypass()
	return w.ResponseWriter.Write(p)
}

func (w *cacheStatusRW) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Flush implements http.Flusher.
func (w *cacheStatusRW) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker.
func (w *cacheStatusRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Push implements http.Pusher.
func (w *cacheStatusRW) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
