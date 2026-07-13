package plugin

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/authn"
	"github.com/moonrhythm/parapet/pkg/headers"
	"gopkg.in/yaml.v3"
)

// denyAll mounts a middleware that answers 403 Forbidden to every request,
// without ever reaching the upstream. Used when an auth annotation is
// present but malformed: failing open (mounting nothing) would let
// unauthenticated traffic through an ingress that declares itself gated, so
// a bad annotation must fail closed instead.
func denyAll(ctx Context) {
	ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}))
}

var authHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	// A forward-auth probe treats the auth server's response status as the
	// verdict (2xx allows; anything else is relayed to the client). It must
	// therefore NOT follow redirects: an auth server that denies by sending
	// "302 -> login page" would otherwise be followed to the login page's 200,
	// which reads as a 2xx "allow" and bypasses auth for every gated request.
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	},
}

// BasicAuth adds basic auth
func BasicAuth(ctx Context) {
	ba := ctx.Ingress.Annotations[namespace+"/basic-auth"]
	if ba == "" {
		return
	}

	xs := strings.SplitN(ba, ":", 2)
	if len(xs) != 2 {
		slog.Error("plugin/BasicAuth: malformed basic-auth annotation, failing closed",
			"ingress", ctx.ingressID())
		denyAll(ctx)
		return
	}
	user, pass := xs[0], xs[1]
	if user == "" || pass == "" {
		slog.Error("plugin/BasicAuth: malformed basic-auth annotation, failing closed",
			"ingress", ctx.ingressID())
		denyAll(ctx)
		return
	}

	ctx.Use(authn.Basic(user, pass))
}

// ForwardAuth adds forward auth
func ForwardAuth(ctx Context) {
	a := ctx.Ingress.Annotations[namespace+"/forward-auth"]
	if a == "" {
		return
	}
	var obj struct {
		URL                 string   `yaml:"url"`
		AuthRequestHeaders  []string `yaml:"authRequestHeaders"`
		AuthResponseHeaders []string `yaml:"authResponseHeaders"`
	}
	err := yaml.Unmarshal([]byte(a), &obj)
	if err != nil {
		slog.Error("plugin/ForwardAuth: malformed forward-auth annotation, failing closed",
			"ingress", ctx.ingressID(), "error", err)
		denyAll(ctx)
		return
	}
	if obj.URL == "" {
		slog.Error("plugin/ForwardAuth: malformed forward-auth annotation, failing closed",
			"ingress", ctx.ingressID(), "error", "missing url")
		denyAll(ctx)
		return
	}
	u, err := url.Parse(obj.URL)
	if err != nil {
		slog.Error("plugin/ForwardAuth: malformed forward-auth annotation, failing closed",
			"ingress", ctx.ingressID(), "error", err)
		denyAll(ctx)
		return
	}
	// Make every response on a forward-auth-gated ingress non-cacheable at the
	// out-of-cluster edge response cache. That cache is honor-origin and its key
	// ignores Cookie, so a cached 200 for a gated host would be served to
	// anonymous users (forward-auth gates the request path, not a cache hit that
	// answers before the request ever reaches here). Cache-Control: private
	// makes the edge (a shared cache) refuse to store or serve it — and the edge
	// honors private even under an aggressive cache-override, so a force-cache
	// rule can't defeat it. Installed BEFORE the authenticator so it is
	// outermost: it overrides whatever Cache-Control the upstream sent and also
	// covers the auth deny/redirect response.
	ctx.Use(headers.SetResponse("Cache-Control", "private"))
	ctx.Use(authn.ForwardAuthenticator{
		URL:                 u,
		Client:              authHTTPClient,
		AuthRequestHeaders:  obj.AuthRequestHeaders,
		AuthResponseHeaders: obj.AuthResponseHeaders,
	})
}
