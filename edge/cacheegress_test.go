package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// knownCacheHost reports whether the given host is "known" for test purposes.
var knownCacheHost = func(h string) bool { return h == "known.example.com" }

// serveCacheEgress drives one request through the CacheEgress middleware.
// The inner handler sets the given X-Cache header value (empty = don't set)
// and writes body.
func serveCacheEgress(t *testing.T, host, xCache string, body []byte) {
	t.Helper()
	mw := CacheEgress(knownCacheHost)
	h := mw.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if xCache != "" {
			w.Header().Set("X-Cache", xCache)
		}
		if len(body) > 0 {
			_, _ = w.Write(body)
		}
	}))
	r := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	r.Host = host
	h.ServeHTTP(httptest.NewRecorder(), r)
}

// cacheEgressCount reads the current counter value for the given host+result.
// cacheEgressRegister() must have been called first (CacheEgress() does this).
func cacheEgressCount(host, result string) float64 {
	return testutil.ToFloat64(cacheEgressVec.WithLabelValues(host, result, edgeID))
}

func TestCacheEgressHITCountsBytes(t *testing.T) {
	// Ensure vec is registered before reading counters.
	mw := CacheEgress(knownCacheHost)
	_ = mw

	before := cacheEgressCount("known.example.com", "HIT")
	serveCacheEgress(t, "known.example.com", "HIT", []byte("hello world")) // 11 bytes
	after := cacheEgressCount("known.example.com", "HIT")
	if got := after - before; got != 11 {
		t.Errorf("HIT bytes: got %.0f, want 11", got)
	}
}

func TestCacheEgressSTALECountsBytes(t *testing.T) {
	mw := CacheEgress(knownCacheHost)
	_ = mw

	before := cacheEgressCount("known.example.com", "STALE")
	serveCacheEgress(t, "known.example.com", "STALE", []byte("stale body")) // 10 bytes
	after := cacheEgressCount("known.example.com", "STALE")
	if got := after - before; got != 10 {
		t.Errorf("STALE bytes: got %.0f, want 10", got)
	}
}

func TestCacheEgressMISSCountsBytes(t *testing.T) {
	mw := CacheEgress(knownCacheHost)
	_ = mw

	before := cacheEgressCount("known.example.com", "MISS")
	serveCacheEgress(t, "known.example.com", "MISS", []byte("miss body!!")) // 11 bytes
	after := cacheEgressCount("known.example.com", "MISS")
	if got := after - before; got != 11 {
		t.Errorf("MISS bytes: got %.0f, want 11", got)
	}
}

func TestCacheEgressUnknownHostCollapsesToOther(t *testing.T) {
	mw := CacheEgress(knownCacheHost)
	_ = mw

	before := cacheEgressCount("other", "HIT")
	serveCacheEgress(t, "evil.example.net", "HIT", []byte("abc")) // unknown host → "other"
	after := cacheEgressCount("other", "HIT")
	if got := after - before; got != 3 {
		t.Errorf("unknown host: got %.0f under \"other\", want 3", got)
	}
}

func TestCacheEgressWeirdXCacheCollapsesToOther(t *testing.T) {
	mw := CacheEgress(knownCacheHost)
	_ = mw

	before := cacheEgressCount("known.example.com", "other")
	// "REVALIDATED" is not a known result value; it must collapse to "other".
	serveCacheEgress(t, "known.example.com", "REVALIDATED", []byte("xyz"))
	after := cacheEgressCount("known.example.com", "other")
	if got := after - before; got != 3 {
		t.Errorf("weird X-Cache: got %.0f under \"other\", want 3", got)
	}
}

func TestCacheEgressNoHeaderRecordsNothing(t *testing.T) {
	// Ensure vec is registered so CollectAndCount has a baseline.
	CacheEgress(knownCacheHost) //nolint:errcheck

	countBefore := testutil.CollectAndCount(cacheEgressVec)
	// No X-Cache header: cache bypass / non-cache response — must not add series.
	serveCacheEgress(t, "known.example.com", "", []byte("bypass body"))
	countAfter := testutil.CollectAndCount(cacheEgressVec)
	if countAfter > countBefore {
		t.Errorf("no X-Cache: series count went from %d to %d, want no new series", countBefore, countAfter)
	}
}

func TestCacheEgressBytesAccumulate(t *testing.T) {
	mw := CacheEgress(knownCacheHost)
	_ = mw

	before := cacheEgressCount("known.example.com", "HIT")
	for i := 0; i < 5; i++ {
		serveCacheEgress(t, "known.example.com", "HIT", []byte("ab")) // 2 bytes each
	}
	after := cacheEgressCount("known.example.com", "HIT")
	if got := after - before; got != 10 {
		t.Errorf("accumulate: got %.0f, want 10 (5×2 bytes)", got)
	}
}

func TestCacheResultLabel(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"HIT", "HIT"},
		{"STALE", "STALE"},
		{"MISS", "MISS"},
		{"BYPASS", "other"},
		{"STALE_ERROR", "other"},
		{"revalidated", "other"},
	}
	for _, c := range cases {
		if got := cacheResultLabel(c.in); got != c.want {
			t.Errorf("cacheResultLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCacheEgressZeroByteHITRecordsZero(t *testing.T) {
	mw := CacheEgress(knownCacheHost)
	_ = mw

	before := cacheEgressCount("known.example.com", "HIT")
	serveCacheEgress(t, "known.example.com", "HIT", nil) // no body
	after := cacheEgressCount("known.example.com", "HIT")
	// 0 bytes added; counter must not go backward.
	if after < before {
		t.Errorf("zero-byte HIT: counter went backwards: %v -> %v", before, after)
	}
}
