package plugin_test

import (
	"bytes"
	"log/slog"
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
	ctx.Use(state.Middleware(true))
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

func TestRedirectRules(t *testing.T) {
	t.Parallel()

	config := `
example.com: https://www.example.com
api.example.com: 308,https://www.example.com/api`
	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/redirect": config,
				},
			},
			Spec: networking.IngressSpec{
				Rules: []networking.IngressRule{
					{Host: "example.com"},
					{Host: "api.example.com"},
				},
			},
		},
		Routes: map[string]http.Handler{},
	}
	RedirectRules(ctx)

	t.Run("Default status code", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		w := httptest.NewRecorder()
		ctx.Routes[r.Host+"/"].ServeHTTP(w, r)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://www.example.com", w.Header().Get("Location"))
	})

	t.Run("Custom status code", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil)
		w := httptest.NewRecorder()
		ctx.Routes[r.Host+"/"].ServeHTTP(w, r)
		assert.Equal(t, 308, w.Code)
		assert.Equal(t, "https://www.example.com/api", w.Header().Get("Location"))
	})
}

func TestRedirectRulesSkipsInvalidEntries(t *testing.T) {
	t.Parallel()

	// A mix of valid rules with one invalid (empty target) entry. The invalid
	// entry must be skipped without dropping the valid rules — regardless of
	// Go's randomized map iteration order.
	config := `
a.example.com: https://target-a.example.com
b.example.com: https://target-b.example.com
c.example.com: https://target-c.example.com
d.example.com: https://target-d.example.com
bad.example.com: ""`
	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/redirect": config,
				},
			},
			Spec: networking.IngressSpec{
				Rules: []networking.IngressRule{
					{Host: "a.example.com"},
					{Host: "b.example.com"},
					{Host: "c.example.com"},
					{Host: "d.example.com"},
					{Host: "bad.example.com"},
				},
			},
		},
		Routes: map[string]http.Handler{},
	}
	RedirectRules(ctx)

	for _, h := range []string{"a.example.com/", "b.example.com/", "c.example.com/", "d.example.com/"} {
		assert.Contains(t, ctx.Routes, h, "valid rule must be registered even when another entry is invalid")
	}
	assert.NotContains(t, ctx.Routes, "bad.example.com/")
}

func TestRedirectRulesHostOwnership(t *testing.T) {
	t.Parallel()

	config := `
owned.example.com: https://target.example.com
foo.wild.example.com: https://target-wild.example.com
owned.example.com/old: https://target-path.example.com
unowned.example.com: https://evil.example.com
tls.example.com: https://target-tls.example.com`
	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns",
				Name:      "ing",
				Annotations: map[string]string{
					"parapet.moonrhythm.io/redirect": config,
				},
			},
			Spec: networking.IngressSpec{
				Rules: []networking.IngressRule{
					{Host: "owned.example.com"},
					{Host: "*.wild.example.com"},
				},
				TLS: []networking.IngressTLS{
					{Hosts: []string{"tls.example.com"}},
				},
			},
		},
		Routes: map[string]http.Handler{},
	}
	RedirectRules(ctx)

	// exact-owned host (via spec.rules) registered
	assert.Contains(t, ctx.Routes, "owned.example.com/")
	// wildcard-owned source registered (owned "*.wild.example.com" matches "foo.wild.example.com")
	assert.Contains(t, ctx.Routes, "foo.wild.example.com/")
	// path-bearing source checked on its host part (trailing slash normalized)
	assert.Contains(t, ctx.Routes, "owned.example.com/old/")
	// host owned via spec.tls[].hosts registered
	assert.Contains(t, ctx.Routes, "tls.example.com/")
	// unowned host must be skipped — the hijack this fix prevents
	assert.NotContains(t, ctx.Routes, "unowned.example.com/")
}

func TestRedirectRulesNon3xxStatusSkipped(t *testing.T) {
	t.Parallel()

	config := `
owned.example.com: 200,https://target.example.com
ok.example.com: 301,https://target-ok.example.com`
	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/redirect": config,
				},
			},
			Spec: networking.IngressSpec{
				Rules: []networking.IngressRule{
					{Host: "owned.example.com"},
					{Host: "ok.example.com"},
				},
			},
		},
		Routes: map[string]http.Handler{},
	}
	RedirectRules(ctx)

	// a non-3xx status is rejected entirely (not treated as a URL)
	assert.NotContains(t, ctx.Routes, "owned.example.com/")

	// a valid "301,url" still works
	if assert.Contains(t, ctx.Routes, "ok.example.com/") {
		r := httptest.NewRequest(http.MethodGet, "http://ok.example.com/", nil)
		w := httptest.NewRecorder()
		ctx.Routes["ok.example.com/"].ServeHTTP(w, r)
		assert.Equal(t, http.StatusMovedPermanently, w.Code)
		assert.Equal(t, "https://target-ok.example.com", w.Header().Get("Location"))
	}
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

func TestBodyLimitInvalidValue(t *testing.T) {
	t.Parallel()

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/body-limitrequest": "not-a-number",
				},
			},
		},
	}
	BodyLimit(ctx) // must not panic on a malformed value

	// an invalid annotation must be ignored, not silently enforced as a limit
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	r.ContentLength = 1 << 30
	var called bool
	ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(w, r)
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpstreamProtocol(t *testing.T) {
	t.Parallel()

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/upstream-protocol": "https",
				},
			},
		},
	}
	UpstreamProtocol(ctx)

	var called bool
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "https", r.URL.Scheme)
		called = true
	})).ServeHTTP(w, r)
	assert.True(t, called)
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

func TestAllowRemote(t *testing.T) {
	t.Parallel()

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"parapet.moonrhythm.io/allow-remote": "192.168.0.0/24,127.0.0.1/32",
				},
			},
		},
	}
	AllowRemote(ctx)

	t.Run("Allow", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		r.RemoteAddr = "192.168.0.32:1234"
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Deny", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		r.RemoteAddr = "192.168.1.32:1234"
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Skip acme-challenge", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/xxx", nil)
		w := httptest.NewRecorder()
		r.RemoteAddr = "192.168.1.32:1234"
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// X-Real-Ip is the parapet-resolved client IP (set by the trust middleware;
	// overwritten for untrusted peers, so it is safe to trust mid-chain). It must
	// take precedence over RemoteAddr, which behind the edge/any trusted L7 hop is
	// only the hop's IP.
	t.Run("X-Real-Ip allow overrides denying RemoteAddr", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Real-Ip", "192.168.0.32")
		r.RemoteAddr = "10.0.0.1:1234" // hop IP, not in the allow-list
		w := httptest.NewRecorder()
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("X-Real-Ip deny overrides allowing RemoteAddr", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Real-Ip", "192.168.1.32")
		r.RemoteAddr = "127.0.0.1:1234" // hop IP, in the allow-list
		w := httptest.NewRecorder()
		var called bool
		ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})).ServeHTTP(w, r)
		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestAllowRemoteAllInvalidCIDRsLogsAndBlocks(t *testing.T) {
	// Not parallel: temporarily swaps the slog default to capture output. (Go runs
	// non-parallel tests sequentially, so no concurrent slog user races the swap.)
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})))
	defer slog.SetDefault(prev)

	ctx := Context{
		Middlewares: &parapet.Middlewares{},
		Ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns",
				Name:      "ing",
				Annotations: map[string]string{
					// a bare IP (no /mask) is rejected by net.ParseCIDR, so the whole
					// allow-list ends up empty → the ingress would 403 all traffic.
					"parapet.moonrhythm.io/allow-remote": "203.0.113.5",
				},
			},
		},
	}
	AllowRemote(ctx)

	logs := buf.String()
	assert.Contains(t, logs, "invalid CIDR", "the malformed entry must be logged")
	assert.Contains(t, logs, "block all traffic", "the total-block outcome must be surfaced")

	// behavior is fail-closed: every non-acme request is forbidden
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:1234"
	w := httptest.NewRecorder()
	var called bool
	ctx.ServeHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(w, r)
	assert.False(t, called)
	assert.Equal(t, http.StatusForbidden, w.Code)
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

func TestForwardAuthCacheControl(t *testing.T) {
	t.Parallel()

	// Auth endpoint that allows every request (200).
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer authSrv.Close()

	// An upstream that tries to make its response publicly cacheable — exactly
	// the leak the override must defeat at the edge.
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.WriteHeader(http.StatusOK)
	})

	t.Run("gated ingress forces private and overrides the upstream", func(t *testing.T) {
		ctx := Context{
			Middlewares: &parapet.Middlewares{},
			Ingress: &networking.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"parapet.moonrhythm.io/forward-auth": "url: " + authSrv.URL,
					},
				},
			},
		}
		ForwardAuth(ctx)

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		ctx.ServeHandler(upstream).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
		// private wins, the upstream's public/max-age is gone (clean override).
		assert.Equal(t, "private", w.Header().Get("Cache-Control"))
	})

	t.Run("non-gated ingress leaves the upstream Cache-Control untouched", func(t *testing.T) {
		ctx := Context{
			Middlewares: &parapet.Middlewares{},
			Ingress: &networking.Ingress{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
			},
		}
		ForwardAuth(ctx)

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		ctx.ServeHandler(upstream).ServeHTTP(w, r)

		assert.Equal(t, "public, max-age=600", w.Header().Get("Cache-Control"))
	})
}
