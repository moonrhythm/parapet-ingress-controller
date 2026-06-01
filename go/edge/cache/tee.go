package cache

import (
	"net/http"
	"os"
	"sort"
	"time"
)

// hopByHop headers are connection-specific and must not be stored in (or served
// from) the shared cache. ReverseProxy already strips most from the upstream
// response; we strip again defensively when snapshotting for the sidecar.
var hopByHop = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
}

// teeWriter wraps the client ResponseWriter on a cache fill (the leader path). It
// streams the response to the client AND, when the response is cacheable, tees
// the body to a temp file. On finish it commits the entry iff the body is
// complete (Content-Length matched, or HEAD), guaranteeing a truncated response
// is never stored.
type teeWriter struct {
	rw         http.ResponseWriter
	r          *http.Request
	c          *Cache
	method     string
	primaryHex string

	wroteHeader bool
	status      int
	caching     bool
	aborted     bool

	tmp        *os.File
	storeKey   string
	written    int64
	contentLen int64
	hasCL      bool
	freshUntil time.Time
	vary       []string // sorted, lowercased
	metaHeader http.Header
}

func (tw *teeWriter) Header() http.Header { return tw.rw.Header() }

func (tw *teeWriter) WriteHeader(code int) {
	if tw.wroteHeader {
		return
	}
	tw.wroteHeader = true
	tw.status = code

	h := tw.rw.Header()
	dec := decide(tw.method, code, h, tw.c.cfg.MaxFileSize, time.Now())
	if dec.cacheable {
		vary := append([]string(nil), dec.vary...)
		sort.Strings(vary)
		// Store under the key derived from THIS response's Vary + the request's
		// values, so a later lookup matches once the Vary map is learned.
		storeKey := variantHashFor(tw.primaryHex, vary, tw.r.Header)
		if tmp, err := tw.c.store.newTemp(storeKey); err == nil {
			tw.tmp = tmp
			tw.storeKey = storeKey
			tw.caching = true
			tw.vary = vary
			tw.freshUntil = dec.freshUntil
			tw.metaHeader = sanitizeHeader(h)
			if cl, ok := contentLength(h); ok {
				tw.hasCL = true
				tw.contentLen = cl
			}
		}
	}
	h.Set("X-Cache", "MISS")
	tw.rw.WriteHeader(code)
}

func (tw *teeWriter) Write(p []byte) (int, error) {
	if !tw.wroteHeader {
		tw.WriteHeader(http.StatusOK)
	}
	n, err := tw.rw.Write(p)
	if tw.caching && !tw.aborted {
		switch {
		case tw.written+int64(len(p)) > tw.c.cfg.MaxFileSize:
			tw.abort() // oversize -> stop caching, client still gets the full response
		default:
			if _, werr := tw.tmp.Write(p); werr != nil {
				tw.abort()
			} else {
				tw.written += int64(len(p))
			}
		}
	}
	return n, err
}

// abort stops caching this response and discards the temp body.
func (tw *teeWriter) abort() {
	tw.aborted = true
	tw.caching = false
	if tw.tmp != nil {
		name := tw.tmp.Name()
		tw.tmp.Close()
		os.Remove(name)
		tw.tmp = nil
	}
}

// finish commits the entry iff the body is complete; a truncated body (written !=
// Content-Length) or an abort discards the temp file. After finish the temp is
// resolved (committed or removed) and tw.tmp is nil. On success it records the
// primary's Vary and admits to the LRU before returning — so by the time the
// caller closes the fill lock's done channel, waiting followers find the entry.
func (tw *teeWriter) finish() {
	if tw.tmp == nil {
		return // not caching
	}
	complete := !tw.aborted && (tw.method == http.MethodHead || (tw.hasCL && tw.written == tw.contentLen))
	if !complete {
		tw.abort()
		return
	}
	m := &meta{
		Status:     tw.status,
		Header:     tw.metaHeader,
		PrimaryHex: tw.primaryHex,
		Vary:       tw.vary,
		Created:    time.Now().UnixNano(),
		FreshUntil: tw.freshUntil.UnixNano(),
		Size:       tw.written,
	}
	tmp := tw.tmp
	tw.tmp = nil // commit consumes (closes) the temp; don't let cleanup touch it
	if err := tw.c.store.commit(tw.storeKey, m, tmp); err != nil {
		return // fail-static: not cached
	}
	tw.c.setPrimaryVary(tw.primaryHex, tw.vary)
	tw.c.admit(tw.storeKey, tw.written)
}

// cleanup is deferred on the leader path so a panic in the upstream handler
// (before finish runs) doesn't leak the open temp file / FD. It is a no-op once
// finish or abort has resolved the temp (tw.tmp == nil).
func (tw *teeWriter) cleanup() {
	if tw.tmp != nil {
		tw.abort()
	}
}

// Flush forwards to the underlying writer so streaming responses still flush.
func (tw *teeWriter) Flush() {
	if f, ok := tw.rw.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying writer to http.ResponseController (Flush/Hijack
// etc. via the standard mechanism).
func (tw *teeWriter) Unwrap() http.ResponseWriter { return tw.rw }

// sanitizeHeader clones h for the sidecar, dropping hop-by-hop headers (and the
// X-Cache tag is not yet set when this is called).
func sanitizeHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		if _, hop := hopByHop[http.CanonicalHeaderKey(k)]; hop {
			continue
		}
		out[k] = append([]string(nil), vs...)
	}
	return out
}
