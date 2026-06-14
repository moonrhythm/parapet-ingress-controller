package plugin

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/moonrhythm/parapet/pkg/authn"
	"github.com/moonrhythm/parapet/pkg/headers"
	"gopkg.in/yaml.v3"
)

var authHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
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
		return
	}
	user, pass := xs[0], xs[1]
	if user == "" || pass == "" {
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
		return
	}
	u, err := url.Parse(obj.URL)
	if err != nil {
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
