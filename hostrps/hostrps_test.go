package hostrps

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/moonrhythm/parapet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func known(hosts ...string) func(string) bool {
	set := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		set[h] = struct{}{}
	}
	return func(h string) bool {
		_, ok := set[h]
		return ok
	}
}

func serve(t *testing.T, m parapet.Middleware, host string, next http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	require.NotNil(t, m)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = host
	m.ServeHandler(next).ServeHTTP(rec, r)
	return rec
}

func TestNew_Off(t *testing.T) {
	t.Parallel()
	assert.Nil(t, New(0, nil, nil))
	assert.Nil(t, New(-1, nil, nil))
}

func TestNew_CapsKnownHostAndSetsRetryAfter(t *testing.T) {
	t.Parallel()
	isKnown := known("a.example.com")
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for range 5 {
		var hits atomic.Int32
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			ok.ServeHTTP(w, r)
		})
		m := New(2, isKnown, nil)
		w1 := serve(t, m, "a.example.com", inner)
		if w1.Code != http.StatusOK {
			continue // window boundary between construction and first request
		}
		w2 := serve(t, m, "a.example.com", inner)
		if w2.Code != http.StatusOK {
			continue
		}
		w3 := serve(t, m, "a.example.com", inner)
		if hits.Load() != 2 {
			continue
		}
		require.Equal(t, http.StatusServiceUnavailable, w3.Code)
		assert.Equal(t, "Service Unavailable\n", w3.Body.String())
		assert.Equal(t, "1", w3.Header().Get("Retry-After"))
		return
	}
	t.Fatal("could not land 2+1 requests in the same 1s window after 5 attempts")
}

func TestNew_KnownHostsIndependent(t *testing.T) {
	t.Parallel()
	isKnown := known("a.example.com", "b.example.com")
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for range 5 {
		m := New(1, isKnown, nil)
		wa := serve(t, m, "a.example.com", ok)
		if wa.Code != http.StatusOK {
			continue
		}
		wb := serve(t, m, "b.example.com", ok)
		if wb.Code != http.StatusOK {
			t.Fatal("host B must not share host A's bucket")
		}
		wa2 := serve(t, m, "a.example.com", ok)
		if wa2.Code == http.StatusOK {
			continue // boundary
		}
		require.Equal(t, http.StatusServiceUnavailable, wa2.Code)
		return
	}
	t.Fatal("could not land independent-host sequence in the same 1s window after 5 attempts")
}

func TestNew_UnknownHostsShareOther(t *testing.T) {
	t.Parallel()
	isKnown := known("a.example.com")
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for range 5 {
		m := New(1, isKnown, nil)
		w1 := serve(t, m, "x.example.com", ok)
		if w1.Code != http.StatusOK {
			continue
		}
		w2 := serve(t, m, "y.example.com", ok)
		if w2.Code == http.StatusOK {
			continue
		}
		require.Equal(t, http.StatusServiceUnavailable, w2.Code)
		assert.Equal(t, http.StatusOK, serve(t, m, "a.example.com", ok).Code,
			"known host is not collapsed into other")
		return
	}
	t.Fatal("could not land unknown-host collapse in the same 1s window after 5 attempts")
}

func TestNew_OnLimitedCollapsedHost(t *testing.T) {
	t.Parallel()
	isKnown := known("a.example.com")
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for range 5 {
		var got string
		m := New(1, isKnown, func(h string) { got = h })
		if serve(t, m, "x.example.com", ok).Code != http.StatusOK {
			continue
		}
		if serve(t, m, "y.example.com", ok).Code == http.StatusOK {
			continue
		}
		assert.Equal(t, collapsedHost, got)
		return
	}
	t.Fatal("could not land OnLimited in the same 1s window after 5 attempts")
}

func TestNew_LimitedDoesNotCallNext(t *testing.T) {
	t.Parallel()
	for range 5 {
		var admitted, reached atomic.Int32
		pass := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			admitted.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		})
		m := New(1, known("a.example.com"), nil)
		if serve(t, m, "a.example.com", pass).Code != http.StatusOK {
			continue
		}
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			reached.Add(1)
		})
		w := serve(t, m, "a.example.com", next)
		if w.Code == http.StatusOK {
			continue // window boundary; the second request was admitted
		}
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		require.Equal(t, int32(1), admitted.Load())
		require.Equal(t, int32(0), reached.Load(), "next handler must not run on a limited request")
		return
	}
	t.Fatal("could not land a limited request in the same 1s window after 5 attempts")
}
