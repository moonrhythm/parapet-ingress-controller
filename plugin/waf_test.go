package plugin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/waf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/moonrhythm/parapet-ingress-controller/plugin"
)

func TestZoneKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ns, ann, key string
		ok           bool
	}{
		{"cust1", "acme", "cust1/acme", true},
		{"cust1", "  acme  ", "cust1/acme", true},
		{"cust1", "team-x/acme", "team-x/acme", true},
		{"cust1", "", "", false},
		{"cust1", "   ", "", false},
		{"cust1", "ns/", "", false},
		{"cust1", "/name", "", false},
		{"cust1", "a/b/c", "", false},
	}
	for _, tc := range cases {
		key, ok := ZoneKey(tc.ns, tc.ann)
		assert.Equal(t, tc.ok, ok, "ann=%q", tc.ann)
		if tc.ok {
			assert.Equal(t, tc.key, key, "ann=%q", tc.ann)
		}
	}
}

func TestWAFZone(t *testing.T) {
	t.Parallel()

	zone := waf.New()
	require.NoError(t, zone.SetRules([]waf.Rule{{
		ID:         "block-admin",
		Expression: `request.path.startsWith("/admin")`,
		Action:     waf.ActionBlock,
	}}))

	newCtx := func(ann map[string]string) Context {
		return Context{
			Middlewares: &parapet.Middlewares{},
			Ingress: &networking.Ingress{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cust1", Annotations: ann},
			},
		}
	}

	serve := func(ctx Context, target string) (*httptest.ResponseRecorder, bool) {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		w := httptest.NewRecorder()
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, r)
		return w, called
	}

	t.Run("blocks matched request via resolved zone", func(t *testing.T) {
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/waf-zone": "acme"})
		var gotKey string
		WAFZone(func(key string) *waf.WAF { gotKey = key; return zone }, nil)(ctx)

		w, called := serve(ctx, "/admin/users")
		assert.Equal(t, "cust1/acme", gotKey)
		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("non-matching request passes through resolved zone", func(t *testing.T) {
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/waf-zone": "acme"})
		WAFZone(func(string) *waf.WAF { return zone }, nil)(ctx)

		w, called := serve(ctx, "/public")
		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("passes through when zone resolves to nil", func(t *testing.T) {
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/waf-zone": "acme"})
		WAFZone(func(string) *waf.WAF { return nil }, nil)(ctx)

		w, called := serve(ctx, "/admin/users")
		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("no annotation injects no middleware", func(t *testing.T) {
		ctx := newCtx(nil)
		var lookupCalled bool
		WAFZone(func(string) *waf.WAF { lookupCalled = true; return zone }, nil)(ctx)

		w, called := serve(ctx, "/admin")
		assert.True(t, called)
		assert.False(t, lookupCalled)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("skip bypasses the zone without resolving it", func(t *testing.T) {
		// A request the skip predicate matches was already validated at the
		// edge: the zone must not run (a blocking rule passes through) and the
		// live lookup must not even happen.
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/waf-zone": "acme"})
		var lookupCalled bool
		WAFZone(
			func(string) *waf.WAF { lookupCalled = true; return zone },
			func(*http.Request) bool { return true },
		)(ctx)

		w, called := serve(ctx, "/admin/users")
		assert.True(t, called)
		assert.False(t, lookupCalled)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("non-matching skip still evaluates the zone", func(t *testing.T) {
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/waf-zone": "acme"})
		WAFZone(
			func(string) *waf.WAF { return zone },
			func(*http.Request) bool { return false },
		)(ctx)

		w, called := serve(ctx, "/admin/users")
		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}
