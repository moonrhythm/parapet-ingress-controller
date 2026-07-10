// Package corazawaf wraps the OWASP Coraza WAF (github.com/corazawaf/coraza)
// into a hot-swappable, parapet-friendly engine, mirroring how the controller
// uses parapet/pkg/waf for the CEL firewall. It is a signature engine (SecLang /
// OWASP Core Rule Set), complementary to — not a replacement for — the CEL WAF:
// the two run as independent layers.
//
// A compiled coraza.WAF is immutable, so a rule edit builds a new instance and
// swaps it atomically (SetDirectives); an empty ruleset stores nil and the
// middleware becomes a cheap pass-through. All-or-nothing like waf.SetRules — a
// bad ruleset is rejected and the last-good instance stays live.
//
// Only the REQUEST phases run: connection, URI, headers, and phase 2 — which
// always evaluates, even for bodyless requests, because most CRS detections
// (SQLi 942xxx, XSS 941xxx) and the CRS anomaly-blocking evaluation rule
// (949110) are phase 2; request-body bytes feed it only when a byte limit opts
// in. Response-body inspection is deliberately never enabled: it would force
// buffering the response and break the reverse proxy's streaming, the edge
// response cache, and HTTP/2.
//
// The package is pure (no metric/k8s imports), so both the controller and the
// out-of-cluster edge can import it, wiring metrics/logging through the OnMatch
// and Observe callbacks — exactly like wafrule.
package corazawaf

import (
	"bytes"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	coraza "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/moonrhythm/parapet"
)

// MatchEvent is one matched rule, delivered to Options.OnMatch for metrics and
// logging. It carries only what types.MatchedRule exposes: the error callback is
// installed at WAF-build time and cannot see the *http.Request, so request
// context (host, method) is not available here — scope is supplied by the caller
// when it builds the OnMatch closure.
type MatchEvent struct {
	RuleID     int
	Severity   string
	Disruptive bool
	URI        string
	ClientIP   string
	Message    string
}

// Options are the fixed tunables every WAF instance an Instance builds shares.
type Options struct {
	// RootFS is the rule filesystem resolved by Include directives — wire the
	// embedded OWASP CRS (coreruleset.FS) here so a ruleset can `Include
	// @crs-setup.conf.example` + `Include @owasp_crs/*.conf`. Include is a plain
	// fs.ReadFile that globs only when the path contains '*', so the bare
	// `@crs-setup` / `@owasp_crs` forms do not resolve. nil disables
	// bundled-ruleset includes.
	RootFS fs.FS

	// RequestBodyLimit caps request-body inspection, in bytes. <= 0 disables
	// request-body access entirely — no body is buffered, so the request path
	// pays nothing extra (phase-2 rules still evaluate, over the URI, args, and
	// headers only). When > 0, up to this many bytes are fed to Coraza and the
	// body is rebuilt so the upstream still receives it in full.
	RequestBodyLimit int

	// ClientIP resolves the true client IP (parapet's X-Real-IP / X-Forwarded-For
	// precedence), used for Coraza's ProcessConnection and REMOTE_ADDR. nil falls
	// back to the RemoteAddr host.
	ClientIP func(*http.Request) string

	// OnMatch, when set, is called once per matched rule after the request phases
	// run — wire it to metrics and logging (the caller adds the scope label). It
	// reads tx.MatchedRules() rather than Coraza's error callback, so it fires for
	// every match regardless of whether the rule engaged logging.
	OnMatch func(MatchEvent)

	// Observe, when set, is called once per evaluated request with the
	// request-phase evaluation latency and whether the request was blocked.
	Observe func(d time.Duration, blocked bool)
}

// Instance is a hot-swappable Coraza engine. The zero value is not usable; call
// New. It satisfies parapet.Middleware via ServeHandler, so it mounts directly
// in a parapet chain just like waf.WAF.
type Instance struct {
	opts Options
	cur  atomic.Pointer[compiled] // nil = no rules loaded (pass-through)
}

// compiled wraps the immutable coraza.WAF so it can live behind atomic.Pointer
// (which needs a concrete element type, not the WAF interface).
type compiled struct{ waf coraza.WAF }

// New returns an Instance with no rules loaded (a pass-through until
// SetDirectives installs a ruleset).
func New(opts Options) *Instance {
	return &Instance{opts: opts}
}

// SetDirectives compiles the concatenated SecLang documents and swaps them in
// atomically. Empty input (no documents, or only whitespace) unloads the
// ruleset, making the middleware a pass-through — so deleting the backing
// ConfigMap turns the layer off. On a compile error the previous ruleset is kept
// (all-or-nothing) and the error is returned for the caller to log.
func (in *Instance) SetDirectives(docs ...string) error {
	directives := strings.TrimSpace(strings.Join(docs, "\n"))
	if directives == "" {
		in.cur.Store(nil)
		return nil
	}

	cfg := coraza.NewWAFConfig()
	if in.opts.RootFS != nil {
		cfg = cfg.WithRootFS(in.opts.RootFS)
	}
	if in.opts.RequestBodyLimit > 0 {
		cfg = cfg.WithRequestBodyAccess().
			WithRequestBodyLimit(in.opts.RequestBodyLimit).
			WithRequestBodyInMemoryLimit(in.opts.RequestBodyLimit)
	}
	// Response-body access is intentionally never enabled (see package doc).
	// Matches are surfaced from tx.MatchedRules() per request (see ServeHandler),
	// not via WithErrorCallback — the callback fires only for rules that engaged
	// logging, which would silently miss matches for metrics.
	cfg = cfg.WithDirectives(directives)

	w, err := coraza.NewWAF(cfg)
	if err != nil {
		return err // keep last-good
	}
	in.cur.Store(&compiled{waf: w})
	return nil
}

// Loaded reports whether a ruleset is currently installed (false = pass-through).
func (in *Instance) Loaded() bool {
	return in.cur.Load() != nil
}

// ServeHandler implements parapet.Middleware. With no ruleset loaded it is a
// single atomic load then pass-through. Otherwise it runs the request-phase
// rules and, on an interruption, writes the block response without calling next.
func (in *Instance) ServeHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := in.cur.Load()
		if c == nil {
			next.ServeHTTP(w, r)
			return
		}

		tx := c.waf.NewTransaction()
		defer func() {
			tx.ProcessLogging()
			_ = tx.Close()
		}()

		var start time.Time
		if in.opts.Observe != nil {
			start = time.Now()
		}
		it := in.inspectRequest(tx, r)
		if in.opts.Observe != nil {
			in.opts.Observe(time.Since(start), it != nil)
		}
		if onMatch := in.opts.OnMatch; onMatch != nil {
			for _, mr := range tx.MatchedRules() {
				onMatch(toEvent(mr))
			}
		}
		if it != nil {
			handleInterruption(w, r, it)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// inspectRequest feeds the request into the transaction and runs phases 1 and 2,
// returning the first interruption (block) encountered, or nil to proceed.
func (in *Instance) inspectRequest(tx types.Transaction, r *http.Request) *types.Interruption {
	clientIP := in.clientIP(r)
	clientPort := portFromAddr(r.RemoteAddr)
	serverIP, serverPort := serverAddr(r)
	tx.ProcessConnection(clientIP, clientPort, serverIP, serverPort)

	tx.ProcessURI(r.URL.String(), r.Method, httpVersion(r.Proto))

	// Go strips the Host header out of r.Header into r.Host; Coraza needs it back
	// (and SERVER_NAME) to evaluate host-based rules.
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(hostOnly(r.Host))
	}
	for k, vv := range r.Header {
		for _, v := range vv {
			tx.AddRequestHeader(k, v)
		}
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it
	}

	if in.opts.RequestBodyLimit > 0 && r.Body != nil && r.Body != http.NoBody {
		if it := in.feedBody(tx, r); it != nil {
			return it
		}
	}
	// Phase 2 always runs, body or not: most CRS detections (SQLi 942xxx, XSS
	// 941xxx) and the CRS anomaly-blocking evaluation rule (949110) are phase 2,
	// so gating it on a body would leave GET query-string attacks entirely
	// unblocked. With no body fed it evaluates over the URI/args/headers above.
	it, _ := tx.ProcessRequestBody()
	return it
}

// feedBody buffers up to RequestBodyLimit bytes of the request body into the
// transaction (phase 2 itself runs later, unconditionally, in inspectRequest),
// then rebuilds r.Body so the upstream still receives the body in full (the
// buffered prefix followed by whatever remained unread). A read error fails open
// (the body is restored and body inspection skipped) — the WAF must never drop a
// request because its body couldn't be buffered. The returned interruption is
// WriteRequestBody's own, e.g. the body limit reached under a rejecting action.
func (in *Instance) feedBody(tx types.Transaction, r *http.Request) *types.Interruption {
	limit := in.opts.RequestBodyLimit
	var buf bytes.Buffer
	_, err := io.CopyN(&buf, r.Body, int64(limit))
	if err != nil && err != io.EOF {
		// Restore the consumed prefix so the upstream still gets the body, then
		// fail open.
		r.Body = newBodyReadCloser(buf.Bytes(), r.Body)
		return nil
	}

	it, _, _ := tx.WriteRequestBody(buf.Bytes())
	r.Body = newBodyReadCloser(buf.Bytes(), r.Body)
	return it
}

func (in *Instance) clientIP(r *http.Request) string {
	if in.opts.ClientIP != nil {
		if ip := in.opts.ClientIP(r); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleInterruption writes the block response. A redirect action with a target
// becomes an HTTP redirect; everything else (deny / drop) writes the rule's
// status, defaulting to 403.
func handleInterruption(w http.ResponseWriter, r *http.Request, it *types.Interruption) {
	if it.Action == "redirect" && it.Data != "" {
		status := it.Status
		if status == 0 {
			status = http.StatusFound
		}
		http.Redirect(w, r, it.Data, status)
		return
	}
	status := it.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	http.Error(w, http.StatusText(status), status)
}

func toEvent(r types.MatchedRule) MatchEvent {
	return MatchEvent{
		RuleID:     r.Rule().ID(),
		Severity:   r.Rule().Severity().String(),
		Disruptive: r.Disruptive(),
		URI:        r.URI(),
		ClientIP:   r.ClientIPAddress(),
		Message:    r.Message(),
	}
}

// bodyReadCloser presents the buffered prefix followed by the remaining body,
// while delegating Close to the original body so its resources are released.
type bodyReadCloser struct {
	io.Reader
	c io.Closer
}

func (b bodyReadCloser) Close() error { return b.c.Close() }

func newBodyReadCloser(buffered []byte, rest io.ReadCloser) io.ReadCloser {
	return bodyReadCloser{
		Reader: io.MultiReader(bytes.NewReader(buffered), rest),
		c:      rest,
	}
}

func portFromAddr(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// serverAddr returns the local (server) IP and port from the connection's
// LocalAddr, stashed in the request context by net/http. Best-effort: empty/0
// when unavailable, which Coraza tolerates.
func serverAddr(r *http.Request) (string, int) {
	la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || la == nil {
		return "", 0
	}
	if tcp, ok := la.(*net.TCPAddr); ok {
		return tcp.IP.String(), tcp.Port
	}
	host, p, err := net.SplitHostPort(la.String())
	if err != nil {
		return "", 0
	}
	n, _ := strconv.Atoi(p)
	return host, n
}

func httpVersion(proto string) string {
	return strings.TrimPrefix(proto, "HTTP/")
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// Ensure Instance satisfies parapet.Middleware.
var _ parapet.Middleware = (*Instance)(nil)
