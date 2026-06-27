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
	"github.com/moonrhythm/parapet-ingress-controller/transformrule"
)

func TestTransformZone(t *testing.T) {
	t.Parallel()

	newZone := func(t *testing.T) *transformrule.Zone {
		z, err := transformrule.Parse(transformrule.Options{}, `
transforms:
- id: hsts
  phase: response
  ops:
  - type: set-header
    name: Strict-Transport-Security
    value: max-age=63072000
  priority: 0
`)
		require.NoError(t, err)
		return z
	}

	newCtx := func(ann map[string]string) Context {
		return Context{
			Middlewares: &parapet.Middlewares{},
			Ingress: &networking.Ingress{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cust1", Name: "web", Annotations: ann},
			},
		}
	}

	serve := func(ctx Context) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, r)
		return w
	}

	t.Run("applies the resolved zone", func(t *testing.T) {
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/transform-zone": "acme"})
		var gotKey string
		zone := newZone(t)
		TransformZone(func(key string) *transformrule.Zone { gotKey = key; return zone })(ctx)

		w := serve(ctx)
		assert.Equal(t, "cust1/acme", gotKey, "bare id resolves in the ingress's namespace")
		assert.Equal(t, "max-age=63072000", w.Header().Get("Strict-Transport-Security"))
	})

	t.Run("cross-namespace reference is honored (stateless config)", func(t *testing.T) {
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/transform-zone": "team-x/acme"})
		var gotKey string
		zone := newZone(t)
		TransformZone(func(key string) *transformrule.Zone { gotKey = key; return zone })(ctx)

		w := serve(ctx)
		assert.Equal(t, "team-x/acme", gotKey)
		assert.Equal(t, "max-age=63072000", w.Header().Get("Strict-Transport-Security"))
	})

	t.Run("passes through when zone resolves to nil", func(t *testing.T) {
		ctx := newCtx(map[string]string{"parapet.moonrhythm.io/transform-zone": "acme"})
		var lookups int
		TransformZone(func(string) *transformrule.Zone { lookups++; return nil })(ctx)

		w := serve(ctx)
		assert.Equal(t, http.StatusOK, w.Code, "missing zone is a safe no-op")
		assert.Empty(t, w.Header().Get("Strict-Transport-Security"))
		assert.Positive(t, lookups, "lookup is consulted live on the request path")
	})

	t.Run("no annotation injects no middleware", func(t *testing.T) {
		ctx := newCtx(nil)
		var lookupCalled bool
		TransformZone(func(string) *transformrule.Zone { lookupCalled = true; return newZone(t) })(ctx)

		w := serve(ctx)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.False(t, lookupCalled, "no annotation => no mount => lookup never called")
	})
}
