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

	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
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
		owned := ownedHosts(ctx.Ingress)
		for srcHost, targetURL := range obj {
			if srcHost == "" || targetURL == "" || strings.HasPrefix(srcHost, "/") {
				continue
			}

			// The Routes map is shared across every ingress in the watch
			// namespace(s) — last writer wins. Only let an ingress register a
			// source host it actually owns via spec.rules / spec.tls, otherwise
			// one tenant could hijack another tenant's host.
			if h, _, _ := strings.Cut(srcHost, "/"); !hostOwned(owned, strings.ToLower(h)) {
				slog.Error("plugin/RedirectRules: source host not owned by ingress, skipping",
					"ingress", ctx.ingressID(), "src", srcHost)
				continue
			}

			if !strings.HasSuffix(srcHost, "/") {
				srcHost += "/"
			}

			target := targetURL
			status := http.StatusFound
			if ts := strings.SplitN(targetURL, ",", 2); len(ts) == 2 {
				st, _ := strconv.Atoi(ts[0])
				// Only a 3xx status makes sense for a redirect; reject anything
				// else outright rather than mistaking "<status>,<url>" for a URL.
				if st < 300 || st > 399 {
					slog.Error("plugin/RedirectRules: redirect status must be 3xx, skipping",
						"ingress", ctx.ingressID(), "src", srcHost, "status", ts[0])
					continue
				}
				status = st
				target = ts[1]
			}

			ctx.Routes[srcHost] = ctx.ServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, status)
			}))
			slog.Debug("plugin/RedirectRules: registered", "src", srcHost, "target", target, "status", status)
		}
	}
}

// ownedHosts returns the lowercased set of hosts the ingress declares via
// spec.rules[].host and spec.tls[].hosts.
func ownedHosts(ing *networking.Ingress) map[string]struct{} {
	owned := make(map[string]struct{})
	for _, rule := range ing.Spec.Rules {
		if rule.Host != "" {
			owned[strings.ToLower(rule.Host)] = struct{}{}
		}
	}
	for _, t := range ing.Spec.TLS {
		for _, h := range t.Hosts {
			if h != "" {
				owned[strings.ToLower(h)] = struct{}{}
			}
		}
	}
	return owned
}

// hostOwned reports whether host is in the owned set, either by exact match or
// by an owned single-label wildcard (owned "*.example.com" matches source
// "foo.example.com") — the same one-label semantics as cert/table.go's climb.
func hostOwned(owned map[string]struct{}, host string) bool {
	if _, ok := owned[host]; ok {
		return true
	}
	if i := strings.IndexByte(host, '.'); i >= 0 {
		if _, ok := owned["*"+host[i:]]; ok {
			return true
		}
	}
	return false
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

	// use wires the decision counter (allowed|limited) before mounting. The
	// name label is <ns>/<name>:<window> — bounded by the ingresses an operator
	// creates (the same argument as rule_id on parapet_waf_matches).
	use := func(rl *ratelimit.RateLimiter, window string) {
		rl.Name = ctx.ingressID() + ":" + window
		rl.Observe = observe.RateLimit(rl.Name)
		ctx.Use(rl)
	}

	if n := rate("/ratelimit-s"); n > 0 {
		use(ratelimit.FixedWindowPerSecond(n), "s")
	}
	if n := rate("/ratelimit-m"); n > 0 {
		use(ratelimit.FixedWindowPerMinute(n), "m")
	}
	if n := rate("/ratelimit-h"); n > 0 {
		use(ratelimit.FixedWindowPerHour(n), "h")
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
