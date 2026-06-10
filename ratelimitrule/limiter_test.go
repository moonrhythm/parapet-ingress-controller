package ratelimitrule_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/moonrhythm/parapet/pkg/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/moonrhythm/parapet-ingress-controller/ratelimitrule"
)

// decisions records observe events per limiter name, for asserting the
// allowed/limited accounting.
type decisions struct {
	mu      sync.Mutex
	allowed map[string]int
	limited map[string]int
}

func newDecisions() *decisions {
	return &decisions{allowed: map[string]int{}, limited: map[string]int{}}
}

func (d *decisions) factory(name string) ratelimit.ObserveFunc {
	return func(e ratelimit.Event) {
		d.mu.Lock()
		defer d.mu.Unlock()
		switch e.Result {
		case ratelimit.ResultAllowed:
			d.allowed[name]++
		case ratelimit.ResultLimited:
			d.limited[name]++
		}
	}
}

func limit(id string, rate int, window string) ratelimitrule.Limit {
	return ratelimitrule.Limit{ID: id, Rate: rate, Window: window}
}

// serve sends one request through l and reports the response plus whether next ran.
func serve(l *ratelimitrule.Limiter, method, target string, hdr map[string]string) (*httptest.ResponseRecorder, bool) {
	r := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	var called bool
	l.Serve(w, r, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	return w, called
}

func TestLimiter_EmptyPassesThrough(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	w, called := serve(l, http.MethodGet, "/", nil)
	assert.True(t, called, "no SetLimits yet: pass-through")
	assert.Equal(t, http.StatusOK, w.Code)

	require.NoError(t, l.SetLimits(nil))
	w, called = serve(l, http.MethodGet, "/", nil)
	assert.True(t, called, "empty batch: pass-through")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLimiter_SetLimitsValidation(t *testing.T) {
	t.Parallel()

	base := limit("ok", 1, "1m")
	cases := []struct {
		name   string
		mutate func(*ratelimitrule.Limit)
	}{
		{"empty id", func(l *ratelimitrule.Limit) { l.ID = "" }},
		{"id with slash", func(l *ratelimitrule.Limit) { l.ID = "a/b" }},
		{"id with colon", func(l *ratelimitrule.Limit) { l.ID = "a:b" }},
		{"id too long", func(l *ratelimitrule.Limit) {
			l.ID = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // 64
		}},
		{"unknown key", func(l *ratelimitrule.Limit) { l.Key = "header" }},
		{"zero rate", func(l *ratelimitrule.Limit) { l.Rate = 0 }},
		{"negative rate", func(l *ratelimitrule.Limit) { l.Rate = -5 }},
		{"missing window", func(l *ratelimitrule.Limit) { l.Window = "" }},
		{"malformed window", func(l *ratelimitrule.Limit) { l.Window = "soon" }},
		{"window too small", func(l *ratelimitrule.Limit) { l.Window = "500ms" }},
		{"window too large", func(l *ratelimitrule.Limit) { l.Window = "2h" }},
		{"unknown algorithm", func(l *ratelimitrule.Limit) { l.Algorithm = "token-bucket" }},
		{"unknown mode", func(l *ratelimitrule.Limit) { l.Mode = "dry-run" }},
		{"status not 429/503", func(l *ratelimitrule.Limit) { l.Status = 403 }},
		{"bad exclude cidr", func(l *ratelimitrule.Limit) { l.Exclude = []string{"10.0.0.0"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &ratelimitrule.Limiter{}
			bad := base
			tc.mutate(&bad)
			assert.Error(t, l.SetLimits([]ratelimitrule.Limit{bad}))
			assert.Nil(t, l.Limits(), "rejected batch must not become live")
		})
	}

	t.Run("duplicate id", func(t *testing.T) {
		l := &ratelimitrule.Limiter{}
		assert.Error(t, l.SetLimits([]ratelimitrule.Limit{limit("a", 1, "1m"), limit("a", 2, "1m")}))
	})
}

func TestLimiter_BadBatchKeepsLastGood(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{limit("only", 1, "1h")}))

	hdr := map[string]string{"X-Real-Ip": "1.2.3.4"}
	_, called := serve(l, http.MethodGet, "/", hdr)
	require.True(t, called)
	w, called := serve(l, http.MethodGet, "/", hdr)
	require.False(t, called)
	require.Equal(t, http.StatusTooManyRequests, w.Code)

	// A bad edit must not drop enforcement (all-or-nothing): the old set — and
	// its consumed budget — stays live.
	require.Error(t, l.SetLimits([]ratelimitrule.Limit{limit("only", 0, "1h")}))
	assert.Equal(t, []string{"only"}, l.IDs())
	w, called = serve(l, http.MethodGet, "/", hdr)
	assert.False(t, called, "previous set still enforcing")
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestLimiter_NormalizedDefaults(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{limit("a", 5, "1m")}))
	got := l.Limits()
	require.Len(t, got, 1)
	assert.Equal(t, "ip", got[0].Key)
	assert.Equal(t, "fixed", got[0].Algorithm)
	assert.Equal(t, "enforce", got[0].Mode)
	assert.Equal(t, http.StatusTooManyRequests, got[0].Status)
	assert.Equal(t, "Too Many Requests", got[0].Message)
	assert.Equal(t, "1m0s", got[0].Window, "window normalized to the parsed duration")
}

func TestLimiter_RejectionResponse(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	lim := limit("a", 1, "1h")
	lim.Message = "slow down"
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{lim}))

	hdr := map[string]string{"X-Real-Ip": "1.2.3.4"}
	_, called := serve(l, http.MethodGet, "/", hdr)
	require.True(t, called)

	w, called := serve(l, http.MethodGet, "/", hdr)
	require.False(t, called)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "slow down\n", w.Body.String())
	if ra := w.Header().Get("Retry-After"); assert.NotEmpty(t, ra, "blocked fixed window advertises a wait") {
		assert.NotEqual(t, "0", ra, "sub-second waits must ceil to >= 1")
	}
}

func TestLimiter_Status503(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	lim := limit("a", 1, "1h")
	lim.Status = http.StatusServiceUnavailable
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{lim}))

	hdr := map[string]string{"X-Real-Ip": "1.2.3.4"}
	serve(l, http.MethodGet, "/", hdr)
	w, called := serve(l, http.MethodGet, "/", hdr)
	assert.False(t, called)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestLimiter_ShadowModeNeverRejects(t *testing.T) {
	t.Parallel()

	d := newDecisions()
	l := &ratelimitrule.Limiter{NamePrefix: "global", Observe: d.factory}
	lim := limit("a", 1, "1h")
	lim.Mode = "shadow"
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{lim}))

	hdr := map[string]string{"X-Real-Ip": "1.2.3.4"}
	for i := 0; i < 3; i++ {
		w, called := serve(l, http.MethodGet, "/", hdr)
		assert.True(t, called, "shadow mode never rejects")
		assert.Equal(t, http.StatusOK, w.Code)
	}
	assert.Equal(t, 1, d.allowed["global:a"])
	assert.Equal(t, 2, d.limited["global:a"], "would-be rejections are counted")
}

func TestLimiter_ExcludeSkipsLimit(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	lim := limit("a", 1, "1h")
	lim.Exclude = []string{"10.0.0.0/8"}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{lim}))

	for i := 0; i < 3; i++ {
		_, called := serve(l, http.MethodGet, "/", map[string]string{"X-Real-Ip": "10.1.2.3"})
		assert.True(t, called, "excluded CIDR is never limited")
	}
	// A non-excluded client still is.
	serve(l, http.MethodGet, "/", map[string]string{"X-Real-Ip": "8.8.8.8"})
	_, called := serve(l, http.MethodGet, "/", map[string]string{"X-Real-Ip": "8.8.8.8"})
	assert.False(t, called)
}

func TestLimiter_ACMEChallengeBypassed(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{limit("a", 1, "1h")}))

	hdr := map[string]string{"X-Real-Ip": "1.2.3.4"}
	for i := 0; i < 3; i++ {
		_, called := serve(l, http.MethodGet, "/.well-known/acme-challenge/tok", hdr)
		assert.True(t, called, "ACME validation is never rate limited")
	}
}

func TestLimiter_IPKeyBuckets(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{limit("a", 1, "1h")}))

	take := func(ip string) bool {
		_, called := serve(l, http.MethodGet, "/", map[string]string{"X-Real-Ip": ip})
		return called
	}

	assert.True(t, take("1.2.3.4"))
	assert.False(t, take("1.2.3.4"), "same IPv4 shares a bucket")
	assert.True(t, take("1.2.3.5"), "different IPv4 is a fresh bucket")

	assert.True(t, take("2001:db8::1"))
	assert.False(t, take("2001:db8::2"), "same IPv6 /64 shares a bucket")
	assert.True(t, take("2001:db8:0:1::1"), "different /64 is a fresh bucket")

	assert.True(t, take("not-an-ip"))
	assert.False(t, take("not-an-ip"), "unparsable X-Real-Ip buckets by raw value")
}

func TestLimiter_HostKeyCollapsesUnknownHosts(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{
		KnownHost: func(host string) bool { return host == "a.example.com" },
	}
	lim := limit("a", 1, "1h")
	lim.Key = "host"
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{lim}))

	take := func(host string) bool {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = host
		w := httptest.NewRecorder()
		var called bool
		l.Serve(w, r, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		return called
	}

	assert.True(t, take("a.example.com"))
	assert.False(t, take("a.example.com"), "known host has its own bucket")
	assert.True(t, take("rnd1.attacker.test"))
	assert.False(t, take("rnd2.attacker.test"), "unknown hosts collapse into one shared bucket")
}

func TestLimiter_IPHostKey(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	lim := limit("a", 1, "1h")
	lim.Key = "ip-host"
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{lim}))

	take := func(ip, host string) bool {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = host
		r.Header.Set("X-Real-Ip", ip)
		w := httptest.NewRecorder()
		var called bool
		l.Serve(w, r, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		return called
	}

	assert.True(t, take("1.2.3.4", "a.example.com"))
	assert.False(t, take("1.2.3.4", "a.example.com"))
	assert.True(t, take("1.2.3.4", "b.example.com"), "same IP, other host: fresh bucket")
	assert.True(t, take("5.6.7.8", "a.example.com"), "other IP, same host: fresh bucket")
}

func TestLimiter_MultiLimitChain(t *testing.T) {
	t.Parallel()

	d := newDecisions()
	l := &ratelimitrule.Limiter{NamePrefix: "zone:ns/z", Observe: d.factory}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{
		limit("loose", 100, "1h"),
		limit("tight", 1, "1h"),
	}))

	hdr := map[string]string{"X-Real-Ip": "1.2.3.4"}
	_, called := serve(l, http.MethodGet, "/", hdr)
	require.True(t, called)
	w, called := serve(l, http.MethodGet, "/", hdr)
	require.False(t, called)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Declaration order: the loose limit was taken (and consumed) before the
	// tight one rejected — same semantics as chained parapet limiters.
	assert.Equal(t, 2, d.allowed["zone:ns/z:loose"])
	assert.Equal(t, 1, d.allowed["zone:ns/z:tight"])
	assert.Equal(t, 1, d.limited["zone:ns/z:tight"])
	assert.Zero(t, d.limited["zone:ns/z:loose"])
}

func TestLimiter_CounterCarryOverAcrossSetLimits(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{limit("a", 1, "1h")}))

	hdr := map[string]string{"X-Real-Ip": "1.2.3.4"}
	_, called := serve(l, http.MethodGet, "/", hdr)
	require.True(t, called)
	_, called = serve(l, http.MethodGet, "/", hdr)
	require.False(t, called, "budget spent")

	// Editing only the message keeps the strategy (and its counters): still spent.
	edited := limit("a", 1, "1h")
	edited.Message = "changed"
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{edited}))
	w, called := serve(l, http.MethodGet, "/", hdr)
	assert.False(t, called, "unchanged shaping config carries counters over")
	assert.Equal(t, "changed\n", w.Body.String(), "but the new message is live")

	// Changing the rate is a legitimate reset: fresh budget.
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{limit("a", 2, "1h")}))
	_, called = serve(l, http.MethodGet, "/", hdr)
	assert.True(t, called, "shaping change resets the strategy")
}

func TestLimiter_ServeHandlerMiddleware(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{limit("a", 1, "1h")}))

	h := l.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	do := func() int {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Real-Ip", "1.2.3.4")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	assert.Equal(t, http.StatusOK, do())
	assert.Equal(t, http.StatusTooManyRequests, do())
}

func TestLimiter_ConcurrentServeAndSwap(t *testing.T) {
	t.Parallel()

	// Hot path under concurrent SetLimits swaps: must be race-free (run with
	// -race) and never panic.
	l := &ratelimitrule.Limiter{}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{limit("a", 1000, "1s")}))

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			hdr := map[string]string{"X-Real-Ip": fmt.Sprintf("10.0.0.%d", n)}
			for j := 0; j < 200; j++ {
				serve(l, http.MethodGet, "/", hdr)
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 50; j++ {
			lim := limit("a", 1000, "1s")
			if j%2 == 0 {
				lim.Rate = 500 // alternate shaping so swaps build fresh strategies
			}
			require.NoError(t, l.SetLimits([]ratelimitrule.Limit{lim}))
		}
	}()
	wg.Wait()
}

func TestLimiter_ShadowDoesNotShortCircuitEnforce(t *testing.T) {
	t.Parallel()

	// The documented rollout puts a shadow limit alongside enforce limits; a
	// tripped shadow limit must fall through to the limits behind it, never
	// short-circuit past them.
	d := newDecisions()
	l := &ratelimitrule.Limiter{NamePrefix: "global", Observe: d.factory}
	shadow := limit("shadow", 1, "1h")
	shadow.Mode = "shadow"
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{shadow, limit("enforce", 2, "1h")}))

	hdr := map[string]string{"X-Real-Ip": "1.2.3.4"}
	_, called := serve(l, http.MethodGet, "/", hdr)
	require.True(t, called, "request 1: both limits admit")
	_, called = serve(l, http.MethodGet, "/", hdr)
	require.True(t, called, "request 2: shadow trips but must not reject NOR skip the enforce limit")
	w, called := serve(l, http.MethodGet, "/", hdr)
	require.False(t, called, "request 3: the enforce limit behind the tripped shadow limit must reject")
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	assert.Equal(t, 1, d.allowed["global:shadow"])
	assert.Equal(t, 2, d.limited["global:shadow"])
	assert.Equal(t, 2, d.allowed["global:enforce"], "enforce kept taking while shadow was tripped")
	assert.Equal(t, 1, d.limited["global:enforce"])
}

func TestLimiter_RetryAfterCeilsSubSecondWaits(t *testing.T) {
	t.Parallel()

	// With a 1s window, a blocked request mid-window has After in (0,1s); the
	// header must ceil to "1" — truncation would emit "Retry-After: 0" and send
	// a compliant client straight into another denial.
	hdr := map[string]string{"X-Real-Ip": "1.2.3.4"}
	for attempt := 0; attempt < 5; attempt++ {
		l := &ratelimitrule.Limiter{}
		require.NoError(t, l.SetLimits([]ratelimitrule.Limit{limit("a", 1, "1s")}))
		_, called := serve(l, http.MethodGet, "/", hdr)
		require.True(t, called)
		w, called := serve(l, http.MethodGet, "/", hdr)
		if called {
			continue // a window boundary fell between the two requests; retry
		}
		assert.Equal(t, "1", w.Header().Get("Retry-After"),
			"sub-second wait must ceil to 1, not truncate to 0")
		return
	}
	t.Fatal("could not get two requests into the same 1s window after 5 attempts")
}

func TestLimiter_HostKeyedExcludeStillResolvesIP(t *testing.T) {
	t.Parallel()

	// On a set whose only limit is host-keyed, the exclude list is the sole
	// reason to resolve the client IP — if that wiring regresses, excludes go
	// silently dead and health checkers start getting limited.
	l := &ratelimitrule.Limiter{}
	lim := limit("a", 1, "1h")
	lim.Key = "host"
	lim.Exclude = []string{"10.0.0.0/8"}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{lim}))

	take := func(ip string) bool {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = "app.example.com"
		r.Header.Set("X-Real-Ip", ip)
		w := httptest.NewRecorder()
		var called bool
		l.Serve(w, r, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		return called
	}

	for i := 0; i < 3; i++ {
		assert.True(t, take("10.1.2.3"), "excluded health checker is never limited on the host bucket")
	}
	assert.True(t, take("8.8.8.8"))
	assert.False(t, take("9.9.9.9"), "non-excluded clients share the host bucket and are limited")
}

func TestLimiter_UnparsableIPIsNotExcluded(t *testing.T) {
	t.Parallel()

	// Fail-closed: an unparsable X-Real-IP must never match an exclude list
	// (flipping this to fail-open would let any client bypass every limit that
	// carries excludes by sending garbage); it buckets by its raw string.
	l := &ratelimitrule.Limiter{}
	lim := limit("a", 1, "1h")
	lim.Exclude = []string{"10.0.0.0/8", "0.0.0.0/0"}
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{lim}))

	hdr := map[string]string{"X-Real-Ip": "not-an-ip"}
	_, called := serve(l, http.MethodGet, "/", hdr)
	require.True(t, called)
	w, called := serve(l, http.MethodGet, "/", hdr)
	assert.False(t, called, "garbage X-Real-Ip is rate limited, not excluded — even against 0.0.0.0/0")
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestLimiter_IPHostKeyCollapsesUnknownHosts(t *testing.T) {
	t.Parallel()

	l := &ratelimitrule.Limiter{
		KnownHost: func(host string) bool { return host == "a.example.com" },
	}
	lim := limit("a", 1, "1h")
	lim.Key = "ip-host"
	require.NoError(t, l.SetLimits([]ratelimitrule.Limit{lim}))

	take := func(ip, host string) bool {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = host
		r.Header.Set("X-Real-Ip", ip)
		w := httptest.NewRecorder()
		var called bool
		l.Serve(w, r, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		return called
	}

	assert.True(t, take("1.2.3.4", "rnd1.attacker.test"))
	assert.False(t, take("1.2.3.4", "rnd2.attacker.test"),
		"unknown hosts collapse inside the ip-host composite too")
	assert.True(t, take("1.2.3.4", "a.example.com"), "the known host keeps its own composite bucket")
	assert.True(t, take("5.6.7.8", "rnd3.attacker.test"), "a different IP is still a fresh bucket")
}
