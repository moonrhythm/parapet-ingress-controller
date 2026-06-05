package plugin

import (
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/block"
	"github.com/moonrhythm/parapet/pkg/body"
	"github.com/moonrhythm/parapet/pkg/header"
	"github.com/moonrhythm/parapet/pkg/hsts"
	"github.com/moonrhythm/parapet/pkg/ratelimit"
	"github.com/moonrhythm/parapet/pkg/stripprefix"
	"gopkg.in/yaml.v3"
	networking "k8s.io/api/networking/v1"

	"github.com/moonrhythm/parapet-ingress-controller/state"
)

const namespace = "parapet.moonrhythm.io"

// Plugin injects middleware or mutate router while reading ingress object
type Plugin func(ctx Context)

// Context holds plugin's relate data
type Context struct {
	*parapet.Middlewares
	Routes  map[string]http.Handler
	Ingress *networking.Ingress
}

// ingressID returns the namespace/name identifier of the ingress, for logs.
func (ctx Context) ingressID() string {
	return ctx.Ingress.Namespace + "/" + ctx.Ingress.Name
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
	if a := ctx.Ingress.Annotations[namespace+"/redirect-https"]; a == "true" {
		ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.RequestURI, "/.well-known/acme-challenge") {
					h.ServeHTTP(w, r)
					return
				}

				proto := header.Get(r.Header, header.XForwardedProto)
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
	if a := ctx.Ingress.Annotations[namespace+"/hsts"]; a != "" {
		var h *hsts.HSTS
		if a == "preload" {
			h = hsts.Preload()
		} else {
			h = hsts.Default()
		}
		// Value is fixed at construction and nothing mutates it downstream,
		// so share a single slice instead of allocating one per response.
		h.ShareValueSlice = true
		ctx.Use(h)
	}
}

// RedirectRules load redirect rules from annotation and inject to routes
func RedirectRules(ctx Context) {
	if a := ctx.Ingress.Annotations[namespace+"/redirect"]; a != "" {
		var obj map[string]string
		if err := yaml.Unmarshal([]byte(a), &obj); err != nil {
			slog.Error("plugin/RedirectRules: invalid redirect annotation, ignoring",
				"ingress", ctx.ingressID(), "error", err)
			return
		}
		for srcHost, targetURL := range obj {
			if srcHost == "" || targetURL == "" || strings.HasPrefix(srcHost, "/") {
				continue
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
			slog.Debug("plugin/RedirectRules: registered", "src", srcHost, "target", target, "status", status)
		}
	}
}

// RateLimit injects rate limit middleware
func RateLimit(ctx Context) {
	rate := func(suffix string) int {
		a := ctx.Ingress.Annotations[namespace+suffix]
		if a == "" {
			return 0
		}
		n, err := strconv.Atoi(a)
		if err != nil {
			slog.Error("plugin/RateLimit: invalid rate, ignoring",
				"ingress", ctx.ingressID(), "annotation", namespace+suffix, "value", a, "error", err)
			return 0
		}
		return n
	}

	if n := rate("/ratelimit-s"); n > 0 {
		ctx.Use(ratelimit.FixedWindowPerSecond(n))
	}
	if n := rate("/ratelimit-m"); n > 0 {
		ctx.Use(ratelimit.FixedWindowPerMinute(n))
	}
	if n := rate("/ratelimit-h"); n > 0 {
		ctx.Use(ratelimit.FixedWindowPerHour(n))
	}
}

// BodyLimit injects body limit middleware
func BodyLimit(ctx Context) {
	if a := ctx.Ingress.Annotations[namespace+"/body-limitrequest"]; a != "" {
		size, err := strconv.ParseInt(a, 10, 64)
		if err != nil {
			slog.Error("plugin/BodyLimit: invalid body-limitrequest, ignoring",
				"ingress", ctx.ingressID(), "value", a, "error", err)
			return
		}
		if size > 0 {
			ctx.Use(body.LimitRequest(size))
		}
	}
}

// UpstreamProtocol changes upstream protocol
func UpstreamProtocol(ctx Context) {
	proto := ctx.Ingress.Annotations[namespace+"/upstream-protocol"]
	scheme := "http"
	switch proto {
	case "", "http":
	case "https":
		scheme = "https"
	default:
		slog.Warn("plugin/UpstreamProtocol: unknown protocol", "protocol", proto)
	}

	ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Scheme = scheme
			h.ServeHTTP(w, r)
		})
	}))
}

// UpstreamHost overrides request's host
func UpstreamHost(ctx Context) {
	host := ctx.Ingress.Annotations[namespace+"/upstream-host"]
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

// UpstreamPath adds path prefix before send to upstream
func UpstreamPath(ctx Context) {
	prefix := ctx.Ingress.Annotations[namespace+"/upstream-path"]
	if prefix == "" {
		return
	}

	targetPath, err := url.ParseRequestURI(prefix)
	if err != nil {
		slog.Warn("plugin/UpstreamPath: can not parse path", "path", prefix, "error", err)
		return
	}

	ctx.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Path = singleJoiningSlash(targetPath.Path, r.URL.Path)

			if targetPath.RawQuery == "" || r.URL.RawQuery == "" {
				r.URL.RawQuery = targetPath.RawQuery + r.URL.RawQuery
			} else {
				r.URL.RawQuery = targetPath.RawQuery + "&" + r.URL.RawQuery
			}

			h.ServeHTTP(w, r)
		})
	}))
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// AllowRemote allows only request come from given ip range
// except /.well-known/acme-challenge
func AllowRemote(ctx Context) {
	allowRemote := ctx.Ingress.Annotations[namespace+"/allow-remote"]
	if allowRemote == "" {
		return
	}

	var allowList []*net.IPNet

	xs := strings.Split(allowRemote, ",")
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		_, allow, err := net.ParseCIDR(x)
		if err != nil {
			slog.Error("plugin/AllowRemote: invalid CIDR, ignoring entry",
				"ingress", ctx.ingressID(), "value", x, "error", err)
			continue
		}
		allowList = append(allowList, allow)
	}
	if len(allowList) == 0 {
		// Every entry was malformed: the block predicate below would 403 ALL
		// traffic (except acme-challenge). Surface it so the outage is diagnosable
		// instead of silently blackholing the ingress.
		slog.Error("plugin/AllowRemote: no valid CIDRs parsed; this ingress will block all traffic",
			"ingress", ctx.ingressID(), "annotation", allowRemote)
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

// StripPrefix strip prefix request path
func StripPrefix(ctx Context) {
	prefix := ctx.Ingress.Annotations[namespace+"/strip-prefix"]
	if prefix == "" {
		return
	}

	ctx.Use(stripprefix.New(prefix))
}
