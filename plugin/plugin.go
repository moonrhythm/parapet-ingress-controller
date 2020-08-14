package plugin

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/authn"
	"github.com/moonrhythm/parapet/pkg/block"
	"github.com/moonrhythm/parapet/pkg/body"
	"github.com/moonrhythm/parapet/pkg/hsts"
	"github.com/moonrhythm/parapet/pkg/ratelimit"
	"gopkg.in/yaml.v2"
	"k8s.io/api/networking/v1beta1"

	"github.com/moonrhythm/parapet-ingress-controller/state"
)

// Plugin injects middleware or mutate router while reading ingress object
type Plugin func(ctx Context)

// Context holds plugin's relate data
type Context struct {
	*parapet.Middlewares
	Routes  map[string]http.Handler
	Ingress *v1beta1.Ingress
}

// InjectStateIngress injects ingress name and namespace to state
func InjectStateIngress(ctx Context) {
	namespace := ctx.Ingress.Namespace
	name := ctx.Ingress.Name
	ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			s := state.Get(ctx)
			s["namespace"] = namespace
			s["ingress"] = name
			h.ServeHTTP(w, r)
		})
	}))
}

// RedirectHTTPS redirects http to https
// except /.well-known/acme-challenge
func RedirectHTTPS(ctx Context) {
	if a := ctx.Ingress.Annotations["parapet.moonrhythm.io/redirect-https"]; a == "true" {
		ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.RequestURI, "/.well-known/acme-challenge") {
					h.ServeHTTP(w, r)
					return
				}

				proto := r.Header.Get("X-Forwarded-Proto")
				if proto == "http" {
					http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
					return
				}

				h.ServeHTTP(w, r)
			})
		}))
	}
}

// InjectHSTS injects hsts header
func InjectHSTS(ctx Context) {
	if a := ctx.Ingress.Annotations["parapet.moonrhythm.io/hsts"]; a != "" {
		if a == "preload" {
			ctx.Use(hsts.Preload())
		} else {
			ctx.Use(hsts.Default())
		}
	}
}

// RedirectRules load redirect rules from annotation and inject to routes
func RedirectRules(ctx Context) {
	if a := ctx.Ingress.Annotations["parapet.moonrhythm.io/redirect"]; a != "" {
		var obj map[string]string
		yaml.Unmarshal([]byte(a), &obj)
		for srcHost, targetURL := range obj {
			if srcHost == "" || targetURL == "" || strings.HasPrefix(srcHost, "/") {
				return
			}
			if !strings.HasSuffix(srcHost, "/") {
				srcHost += "/"
			}

			target := targetURL
			status := http.StatusFound
			if ts := strings.SplitN(targetURL, ",", 2); len(ts) == 2 {
				st, _ := strconv.Atoi(ts[0])
				if st > 0 {
					status = st
					target = ts[1]
				}
			}

			ctx.Routes[srcHost] = ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, status)
			}))
			glog.V(1).Infof("registered: %s ==> %d,%s", srcHost, status, target)
		}
	}
}

// RateLimit injects rate limit middleware
func RateLimit(ctx Context) {
	if a := ctx.Ingress.Annotations["parapet.moonrhythm.io/ratelimit-s"]; a != "" {
		rate, _ := strconv.Atoi(a)
		if rate > 0 {
			ctx.Use(ratelimit.FixedWindowPerSecond(rate))
		}
	}
	if a := ctx.Ingress.Annotations["parapet.moonrhythm.io/ratelimit-m"]; a != "" {
		rate, _ := strconv.Atoi(a)
		if rate > 0 {
			ctx.Use(ratelimit.FixedWindowPerMinute(rate))
		}
	}
	if a := ctx.Ingress.Annotations["parapet.moonrhythm.io/ratelimit-h"]; a != "" {
		rate, _ := strconv.Atoi(a)
		if rate > 0 {
			ctx.Use(ratelimit.FixedWindowPerHour(rate))
		}
	}
}

// BodyLimit injects body limit middleware
func BodyLimit(ctx Context) {
	if a := ctx.Ingress.Annotations["parapet.moonrhythm.io/body-limitrequest"]; a != "" {
		size, _ := strconv.ParseInt(a, 10, 64)
		if size > 0 {
			ctx.Use(body.LimitRequest(size))
		}
	}
}

// UpstreamProtocol changes upstream protocol
func UpstreamProtocol(ctx Context) {
	proto := ctx.Ingress.Annotations["parapet.moonrhythm.io/upstream-protocol"]
	scheme := "http"
	switch proto {
	case "", "http":
	case "https":
		scheme = "https"
	default:
		glog.Warning("unknown protocol", proto)
	}

	ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Scheme = scheme
			h.ServeHTTP(w, r)
		})
	}))
}

func UpstreamHost(ctx Context) {
	host := ctx.Ingress.Annotations["parapet.moonrhythm.io/upstream-host"]
	if host == "" {
		return
	}
	ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Host = host
			h.ServeHTTP(w, r)
		})
	}))
}

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

// AllowRemote allows only request come from given ip range
// except /.well-known/acme-challenge
func AllowRemote(ctx Context) {
	allowRemote := ctx.Ingress.Annotations["parapet.moonrhythm.io/allow-remote"]
	if allowRemote == "" {
		return
	}

	var allowList []*net.IPNet

	xs := strings.Split(allowRemote, ",")
	for _, x := range xs {
		x = strings.TrimSpace(x)
		_, allow, _ := net.ParseCIDR(x)
		if allow != nil {
			allowList = append(allowList, allow)
		}
	}

	m := block.New(func(r *http.Request) bool {
		if strings.HasPrefix(r.RequestURI, "/.well-known/acme-challenge") {
			return false
		}

		remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
		remoteIP := net.ParseIP(remoteHost)
		for _, allow := range allowList {
			if allow.Contains(remoteIP) {
				return false
			}
		}
		return true
	})
	m.Use(parapet.MiddlewareFunc(func(_ http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}))

	ctx.Use(m)
}
