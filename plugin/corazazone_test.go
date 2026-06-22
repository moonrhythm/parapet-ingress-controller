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

	"github.com/moonrhythm/parapet-ingress-controller/corazawaf"
	. "github.com/moonrhythm/parapet-ingress-controller/plugin"
)

func TestCorazaZone(t *testing.T) {
	t.Parallel()

	zone := corazawaf.New(corazawaf.Options{})
	require.NoError(t, zone.SetDirectives(`
SecRuleEngine On
SecRule REQUEST_URI "@contains /admin" "id:7001,phase:1,deny,status:403"
`))

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
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/coraza-zone": "acme"})
		var gotKey string
		CorazaZone(func(key string) *corazawaf.Instance { gotKey = key; return zone })(ctx)

		w, called := serve(ctx, "/admin/users")
		assert.Equal(t, "cust1/acme", gotKey)
		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("cross-namespace ref resolves (the WAF model)", func(t *testing.T) {
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/coraza-zone": "other-ns/shared"})
		var gotKey string
		CorazaZone(func(key string) *corazawaf.Instance { gotKey = key; return zone })(ctx)

		w, called := serve(ctx, "/admin")
		assert.Equal(t, "other-ns/shared", gotKey, "ns/id ref resolves verbatim across namespaces")
		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("non-matching request passes through", func(t *testing.T) {
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/coraza-zone": "acme"})
		CorazaZone(func(string) *corazawaf.Instance { return zone })(ctx)

		w, called := serve(ctx, "/public")
		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("passes through when zone resolves to nil", func(t *testing.T) {
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/coraza-zone": "acme"})
		CorazaZone(func(string) *corazawaf.Instance { return nil })(ctx)

		w, called := serve(ctx, "/admin/users")
		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("no annotation injects no middleware", func(t *testing.T) {
		ctx := newCtx(nil)
		var lookupCalled bool
		CorazaZone(func(string) *corazawaf.Instance { lookupCalled = true; return zone })(ctx)

		w, called := serve(ctx, "/admin")
		assert.True(t, called)
		assert.False(t, lookupCalled)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
