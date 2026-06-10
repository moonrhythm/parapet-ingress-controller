package plugin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/moonrhythm/parapet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/moonrhythm/parapet-ingress-controller/plugin"
	"github.com/moonrhythm/parapet-ingress-controller/ratelimitrule"
)

func TestRateLimitZone(t *testing.T) {
	t.Parallel()

	newZone := func() *ratelimitrule.Limiter {
		zone := &ratelimitrule.Limiter{}
		require.NoError(t, zone.SetLimits([]ratelimitrule.Limit{
			{ID: "per-ip", Rate: 1, Window: "1h"},
		}))
		return zone
	}

	newCtx := func(ann map[string]string) Context {
		return Context{
			Middlewares: &parapet.Middlewares{},
			Ingress: &networking.Ingress{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cust1", Name: "web", Annotations: ann},
			},
		}
	}

	serve := func(ctx Context, ip string) (*httptest.ResponseRecorder, bool) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Real-Ip", ip)
		w := httptest.NewRecorder()
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, r)
		return w, called
	}

	t.Run("limits via resolved zone", func(t *testing.T) {
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/ratelimit-zone": "acme"})
		var gotKey string
		zone := newZone()
		RateLimitZone(func(key string) *ratelimitrule.Limiter { gotKey = key; return zone })(ctx)

		_, called := serve(ctx, "1.2.3.4")
		assert.Equal(t, "cust1/acme", gotKey, "bare id resolves in the ingress's namespace")
		assert.True(t, called)

		w, called := serve(ctx, "1.2.3.4")
		assert.False(t, called)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})

	t.Run("same-namespace explicit reference is honored", func(t *testing.T) {
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/ratelimit-zone": "cust1/acme"})
		var lookups int
		RateLimitZone(func(string) *ratelimitrule.Limiter { lookups++; return newZone() })(ctx)

		_, called := serve(ctx, "1.2.3.4")
		assert.True(t, called)
		assert.Positive(t, lookups)
	})

	t.Run("cross-namespace reference is not honored", func(t *testing.T) {
		// Unlike waf-zone: a rate-limit zone carries shared counter state, so a
		// cross-namespace bind would let one tenant burn another's budgets.
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/ratelimit-zone": "team-x/acme"})
		var lookupCalled bool
		RateLimitZone(func(string) *ratelimitrule.Limiter { lookupCalled = true; return newZone() })(ctx)

		for i := 0; i < 3; i++ {
			w, called := serve(ctx, "1.2.3.4")
			assert.True(t, called, "no middleware injected: requests pass through")
			assert.Equal(t, http.StatusOK, w.Code)
		}
		assert.False(t, lookupCalled)
	})

	t.Run("passes through when zone resolves to nil", func(t *testing.T) {
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/ratelimit-zone": "acme"})
		RateLimitZone(func(string) *ratelimitrule.Limiter { return nil })(ctx)

		for i := 0; i < 3; i++ {
			_, called := serve(ctx, "1.2.3.4")
			assert.True(t, called, "missing zone fails open (global limits still apply upstream)")
		}
	})

	t.Run("no annotation injects no middleware", func(t *testing.T) {
		ctx := newCtx(nil)
		var lookupCalled bool
		RateLimitZone(func(string) *ratelimitrule.Limiter { lookupCalled = true; return newZone() })(ctx)

		_, called := serve(ctx, "1.2.3.4")
		assert.True(t, called)
		assert.False(t, lookupCalled)
	})
}
