package plugin

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/moonrhythm/parapet/pkg/authn"
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
	ba := ctx.Ingress.Annotations["parapet.moonrhythm.io/basic-auth"]
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
	a := ctx.Ingress.Annotations["parapet.moonrhythm.io/forward-auth"]
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
	ctx.Use(authn.ForwardAuthenticator{
		URL:                 u,
		Client:              authHTTPClient,
		AuthRequestHeaders:  obj.AuthRequestHeaders,
		AuthResponseHeaders: obj.AuthResponseHeaders,
	})
}
