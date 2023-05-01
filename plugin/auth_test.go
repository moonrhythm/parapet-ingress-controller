package plugin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/moonrhythm/parapet"
	"github.com/stretchr/testify/assert"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/moonrhythm/parapet-ingress-controller/plugin"
)

func TestBasicAuth(t *testing.T) {
	t.Parallel()

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/basic-auth": "root:password",
				},
			},
		},
	}
	BasicAuth(ctx)

	t.Run("Valid", func(t *testing.T) {
		var called bool
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.SetBasicAuth("root", "password")
		w := httptest.NewRecorder()
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.True(t, called)
	})

	t.Run("Invalid", func(t *testing.T) {
		var called bool
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.SetBasicAuth("admin", "super")
		w := httptest.NewRecorder()
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.False(t, called)
	})

	t.Run("Empty", func(t *testing.T) {
		var called bool
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.False(t, called)
	})
}
