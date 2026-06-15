package plugin_test

import (
	"fmt"
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

func TestForwardAuth(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer super-secret-token" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	config := fmt.Sprintf(`
url: %s
authRequestHeaders:
- authorization
`, ts.URL)

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/forward-auth": config,
				},
			},
		},
	}
	ForwardAuth(ctx)

	t.Run("Valid", func(t *testing.T) {
		var called bool
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer super-secret-token")
		w := httptest.NewRecorder()
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.True(t, called)
	})

	t.Run("Invalid", func(t *testing.T) {
		var called bool
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer wrong-token")
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

// TestForwardAuthDoesNotFollowRedirect guards against a fail-open: an auth
// server that denies by redirecting to a login page (the access.deploys.app
// gate) must have its 302 relayed, never followed. Following "302 -> login"
// to the login page's 200 would read as an "allow" and let every gated
// request through. authHTTPClient must not follow redirects.
func TestForwardAuthDoesNotFollowRedirect(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("login page"))
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer ts.Close()

	config := fmt.Sprintf("\nurl: %s/verify\n", ts.URL)

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/forward-auth": config,
				},
			},
		},
	}
	ForwardAuth(ctx)

	var called bool
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(w, r)

	assert.False(t, called, "upstream must not be reached when auth redirects to login")
	assert.Equal(t, http.StatusFound, w.Code, "auth 302 must be relayed, not followed to a 200")
}
