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
	"github.com/moonrhythm/parapet-ingress-controller/state"
)

func TestInjectStateIngress(t *testing.T) {
	t.Parallel()

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "ingress",
			},
		},
	}
	ctx.Use(state.Middleware())
	InjectStateIngress(ctx)

	var called bool
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := state.Get(r.Context())
		assert.Equal(t, "default", s["namespace"])
		assert.Equal(t, "ingress", s["ingress"])
		called = true
	})).ServeHTTP(w, r)
	assert.True(t, called)
}

func TestRedirectHTTPS(t *testing.T) {
	t.Parallel()

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/redirect-https": "true",
				},
			},
		},
	}
	RedirectHTTPS(ctx)

	t.Run("Redirect HTTP to HTTPS", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		r.Header.Set("X-Forwarded-Proto", "http")
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.False(t, called)
		assert.Equal(t, http.StatusMovedPermanently, w.Code)
	})

	t.Run("Do not redirect HTTPS to HTTPS", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		r.Header.Set("X-Forwarded-Proto", "https")
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Do not redirect HTTP with acme-challenge", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/xxx", nil)
		w := httptest.NewRecorder()
		r.Header.Set("X-Forwarded-Proto", "http")
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.True(t, called)
	})
}

func TestInjectHSTS(t *testing.T) {
	t.Parallel()

	t.Run("Default", func(t *testing.T) {
		ctx := Context{
			Middlewares: &parapet.Middlewares{},
			Ingress: &networking.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"parapet.moonrhythm.io/hsts": "true",
					},
				},
			},
		}
		InjectHSTS(ctx)

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.True(t, called)
		assert.Equal(t, "max-age=31536000", w.Header().Get("Strict-Transport-Security"))
	})

	t.Run("Preload", func(t *testing.T) {
		ctx := Context{
			Middlewares: &parapet.Middlewares{},
			Ingress: &networking.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"parapet.moonrhythm.io/hsts": "preload",
					},
				},
			},
		}
		InjectHSTS(ctx)

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.True(t, called)
		assert.Equal(t, "max-age=63072000; includeSubDomains; preload", w.Header().Get("Strict-Transport-Security"))
	})
}

func TestBodyLimit(t *testing.T) {
	t.Parallel()

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/body-limitrequest": "1024", // 1KiB
				},
			},
		},
	}
	BodyLimit(ctx)

	t.Run("Limit request body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		w := httptest.NewRecorder()
		r.ContentLength = 1024 * 2
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.False(t, called)
		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	})

	t.Run("Do not limit request body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		w := httptest.NewRecorder()
		r.ContentLength = 1024 / 2
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestUpstreamHost(t *testing.T) {
	t.Parallel()

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/upstream-host": "test",
				},
			},
		},
	}
	UpstreamHost(ctx)

	var called bool
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "example.com"
	w := httptest.NewRecorder()
	ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test", r.Host)
		called = true
	})).ServeHTTP(w, r)
	assert.True(t, called)
}

func TestUpstreamPath(t *testing.T) {
	t.Parallel()

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/upstream-path": "/api",
				},
			},
		},
	}
	UpstreamPath(ctx)

	var called bool
	r := httptest.NewRequest(http.MethodGet, "/profile", nil)
	w := httptest.NewRecorder()
	ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/profile", r.URL.Path)
		called = true
	})).ServeHTTP(w, r)
	assert.True(t, called)
}

func TestStripPrefix(t *testing.T) {
	t.Parallel()

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/strip-prefix": "/api",
				},
			},
		},
	}
	StripPrefix(ctx)

	var called bool
	r := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	w := httptest.NewRecorder()
	ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/profile", r.URL.Path)
		called = true
	})).ServeHTTP(w, r)
	assert.True(t, called)
}
