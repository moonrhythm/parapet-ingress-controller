// Command edge-proxy is the out-of-cluster parapet edge proxy (Go). It
// terminates public TLS locally with a cert+key fetched from the in-cluster edge
// control plane, runs the global + zone WAF as an early-drop layer, optionally
// caches responses on disk, and forwards to the in-cluster parapet with the
// X-Forwarded-* headers parapet trusts. See ../../EDGE.md.
//
// This is the Go re-implementation of the former Rust/Pingora edge: same
// control-plane HTTP/JSON contract, same EDGE_* env contract, same per-request
// behavior. It reuses the controller's cert/wafrule/geoip packages and
// parapet/pkg/waf (the CEL engine), so the edge WAF blocks identically to
// parapet — which remains authoritative.
package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/healthz"
	"github.com/moonrhythm/parapet/pkg/host"
	"github.com/moonrhythm/parapet/pkg/logger"
	"github.com/moonrhythm/parapet/pkg/prom"

	"github.com/moonrhythm/parapet-ingress-controller/go/edge"
	"github.com/moonrhythm/parapet-ingress-controller/go/edge/cache"
	"github.com/moonrhythm/parapet-ingress-controller/go/geoip"
)

var version = "HEAD"

func main() {
	httpsListen := envOr("EDGE_HTTPS_LISTEN", "0.0.0.0:443")
	httpListen := envOr("EDGE_HTTP_LISTEN", "0.0.0.0:80")  // "" disables
	metricsListen := envOr("EDGE_METRICS_LISTEN", ":9187") // "" disables
	cpEndpoint := envOr("EDGE_CP_ENDPOINT", "https://controlplane:8443")
	// The control-plane channel carries the bearer token AND the per-domain TLS
	// private key, so require https unless an operator explicitly opts into
	// plaintext on a trusted private network (matching the control plane's own
	// optional plaintext mode). Reject a malformed or accidentally-http endpoint
	// at startup rather than silently sending secrets in the clear.
	if u, err := url.Parse(cpEndpoint); err != nil || u.Host == "" {
		slog.Error("EDGE_CP_ENDPOINT is not a valid URL", "endpoint", cpEndpoint)
		os.Exit(1)
	} else if u.Scheme != "https" && envOr("EDGE_CP_ALLOW_PLAINTEXT", "false") != "true" {
		slog.Error("EDGE_CP_ENDPOINT must be https:// (it carries the bearer token and private keys); set EDGE_CP_ALLOW_PLAINTEXT=true only on a trusted private network",
			"endpoint", cpEndpoint)
		os.Exit(1)
	}
	cpToken := os.Getenv("EDGE_CP_TOKEN")
	if cpToken == "" {
		slog.Error("EDGE_CP_TOKEN is required")
		os.Exit(1)
	}
	var caPEM []byte
	if p := os.Getenv("EDGE_CP_CA"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			caPEM = b
		} else {
			slog.Warn("edge: cannot read EDGE_CP_CA; using system roots", "path", p, "error", err)
		}
	}
	upstreamAddr := envOr("EDGE_UPSTREAM_ADDR", "parapet:80")
	upstreamTLS := envOr("EDGE_UPSTREAM_TLS", "false") == "true"
	upstreamSNI := envOr("EDGE_UPSTREAM_SNI", "")
	refreshInterval := time.Duration(envInt64("EDGE_REFRESH_INTERVAL", 300)) * time.Second
	if refreshInterval <= 0 { // a 0/negative value would panic time.NewTicker
		refreshInterval = 300 * time.Second
	}
	wafEnabled := envOr("EDGE_WAF_ENABLED", "false") == "true"
	disableLog := envOr("DISABLE_LOG", "false") == "true"
	waitBeforeShutdown := time.Duration(envInt64("WAIT_BEFORE_SHUTDOWN", 30)) * time.Second
	domains := splitDomains(os.Getenv("EDGE_DOMAINS"))
	serveAll := len(domains) == 0

	slog.Info("parapet-edge",
		"version", version,
		"https_listen", httpsListen,
		"http_listen", httpListen,
		"cp_endpoint", cpEndpoint,
		"upstream_addr", upstreamAddr,
		"upstream_tls", upstreamTLS,
		"serve_all", serveAll,
		"domains", len(domains),
		"waf_enabled", wafEnabled,
		"refresh_interval", refreshInterval,
	)

	cp, err := edge.NewCpClient(cpEndpoint, cpToken, caPEM)
	if err != nil {
		slog.Error("edge: cannot init control-plane client", "error", err)
		os.Exit(1)
	}
	store := edge.NewCertStore()

	ctx := context.Background()

	if serveAll {
		// On a handshake for an SNI not held, fetch it from the control plane (the
		// handshake blocks on it); the CP's per-token authz still gates which SNIs
		// resolve. The periodic refresh keeps on-demand domains rotated.
		store.SetOnDemand(func(sni string) { edge.RefreshCertOnce(cp, store, sni) })
		slog.Info("edge: EDGE_DOMAINS empty — serving ALL domains (certs fetched on demand)")
	} else {
		loaded := edge.RefreshCertsAll(cp, store, domains)
		slog.Info("edge: initial cert load", "loaded", loaded, "total", len(domains))
	}
	go edge.RunCertRefresh(ctx, cp, store, domains, refreshInterval)

	// Optional edge WAF (early-drop; parapet stays authoritative). GeoIP/ASN are
	// resolved from the TRUE client IP (the edge is the first hop).
	var ewaf *edge.EdgeWAF
	var country func(*http.Request) string
	var asn func(*http.Request) int64
	if wafEnabled {
		country, asn = loadGeoResolvers()
		ewaf = edge.NewEdgeWAF(country, asn)
		edge.RefreshWafOnce(cp, ewaf)
		go edge.RunWafRefresh(ctx, cp, ewaf, refreshInterval)
	}

	// Optional disk-backed response cache (off by default).
	var respCache *cache.Cache
	if envOr("EDGE_CACHE_ENABLED", "false") == "true" {
		cfg := cache.Config{
			Dir:         envOr("EDGE_CACHE_DIR", "/var/cache/parapet-edge"),
			MaxSize:     envInt64("EDGE_CACHE_MAX_SIZE", 1<<30),
			MaxFileSize: envInt64("EDGE_CACHE_MAX_FILE_SIZE", 8<<20),
		}
		c, err := cache.New(cfg)
		if err != nil {
			slog.Error("edge cache: cannot init cache dir; caching disabled", "dir", cfg.Dir, "error", err)
		} else {
			respCache = c
			slog.Info("edge cache enabled (disk-backed)", "dir", cfg.Dir, "max_size", cfg.MaxSize, "max_file", cfg.MaxFileSize)
		}
	}

	forwarder := edge.NewForwarder(upstreamAddr, upstreamTLS, upstreamSNI)

	if metricsListen != "" {
		go func() {
			if err := prom.Start(metricsListen); err != nil {
				slog.Error("edge: metrics listener failed", "error", err)
			}
		}()
	}

	health := healthz.New()

	// Shared middleware chain (both listeners use it). Order mirrors the
	// controller: host normalization, then WAF (global, then host-bound zone)
	// before forwarding; the cache wraps the forwarder; X-Forwarded-Country/-ASN
	// are set just before forwarding.
	m := parapet.Middlewares{}
	m.Use(health)
	m.Use(host.StripPort())
	m.Use(host.ToLower())
	if !disableLog {
		m.Use(logger.Stdout())
	}
	if ewaf != nil {
		m.Use(ewaf.Global())
		m.Use(ewaf.Zone())
	}
	if country != nil || asn != nil {
		m.Use(forwardGeoHeaders(country, asn))
	}
	if respCache != nil {
		m.Use(respCache.Middleware())
	}
	m.Use(forwarder)

	// Readiness: green once the edge has a usable cert (so the LB doesn't send
	// traffic to an edge that would only serve the self-signed fallback). In
	// serve-all mode there is no pre-fetch, so it's ready immediately (certs are
	// fetched on demand). If the initial load failed (control plane down), a
	// background poll flips readiness once the periodic refresh lands a cert.
	if serveAll || store.Loaded() {
		health.SetReady(true)
	} else {
		go func() {
			for !store.Loaded() {
				time.Sleep(2 * time.Second)
			}
			health.SetReady(true)
			slog.Info("edge: ready (first cert loaded)")
		}()
	}

	var wg sync.WaitGroup

	// HTTPS (public TLS terminated locally; SNI cert from the store, self-signed
	// fallback on a miss).
	{
		fallback, err := parapet.GenerateSelfSignCertificate(parapet.SelfSign{CommonName: "parapet-edge"})
		if err != nil {
			slog.Error("edge: cannot generate self-signed fallback", "error", err)
			os.Exit(1)
		}
		s := &parapet.Server{
			Addr:               httpsListen,
			IdleTimeout:        320 * time.Second,
			TCPKeepAlivePeriod: time.Minute,
			GraceTimeout:       time.Minute,
			WaitBeforeShutdown: waitBeforeShutdown,
			Handler:            http.NotFoundHandler(),
			ShareProtoSlice:    true,
			TLSConfig: &tls.Config{
				MinVersion:     tls.VersionTLS12,
				Certificates:   []tls.Certificate{fallback},
				GetCertificate: store.GetCertificate,
			},
		}
		prom.Connections(s)
		prom.Networks(s)
		s.Use(m)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.ListenAndServe(); err != nil {
				slog.Error("edge: https server failed", "error", err)
				os.Exit(1)
			}
		}()
	}

	// Plaintext HTTP (no http->https redirect; forwards with X-Forwarded-Proto:
	// http so parapet's redirect-https plugin decides). "" disables.
	if httpListen != "" {
		s := &parapet.Server{
			Addr:               httpListen,
			IdleTimeout:        60 * time.Second,
			TCPKeepAlivePeriod: time.Minute,
			GraceTimeout:       time.Minute,
			WaitBeforeShutdown: waitBeforeShutdown,
			Handler:            http.NotFoundHandler(),
			H2C:                true,
			ShareProtoSlice:    true,
		}
		prom.Connections(s)
		prom.Networks(s)
		s.Use(m)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.ListenAndServe(); err != nil {
				slog.Error("edge: http server failed", "error", err)
				os.Exit(1)
			}
		}()
	}

	wg.Wait()
}

// forwardGeoHeaders sets X-Forwarded-Country / X-Forwarded-ASN from the GeoIP
// resolvers, overwriting any client value (so it can't be spoofed), only when a
// resolver is non-nil (the DB is loaded). An unplaceable IP yields "XX" / 0.
// Matches the controller's upstream behavior.
func forwardGeoHeaders(country func(*http.Request) string, asn func(*http.Request) int64) parapet.Middleware {
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if country != nil {
				r.Header.Set("X-Forwarded-Country", country(r))
			}
			if asn != nil {
				r.Header.Set("X-Forwarded-ASN", strconv.FormatInt(asn(r), 10))
			}
			h.ServeHTTP(w, r)
		})
	})
}

// loadGeoResolvers opens the GeoIP + ASN databases the same way the controller
// does (WAF_GEOIP_DB / WAF_ASN_DB; "" disables; baked default path; a missing
// default is a quiet no-op, a missing explicit path is logged). Returns nil
// resolvers when a DB isn't loaded (-> request.country "" / request.asn 0).
func loadGeoResolvers() (country func(*http.Request) string, asn func(*http.Request) int64) {
	dbPath := func(env, def string) (string, bool) {
		if v, ok := os.LookupEnv(env); ok {
			return v, true
		}
		return def, false
	}

	if path, explicit := dbPath("WAF_GEOIP_DB", "/geoip/ip-to-country.mmdb"); path != "" {
		db, err := geoip.Open(path)
		switch {
		case err != nil && explicit:
			slog.Error("edge: cannot open geoip database; request.country will be empty", "path", path, "error", err)
		case err != nil:
			slog.Debug("edge: no geoip database at default path; request.country disabled", "path", path)
		default:
			slog.Info("edge: geoip database loaded", "path", path)
			country = func(r *http.Request) string {
				if cc := db.CountryCached(geoip.ClientIP(r)); cc != "" {
					return cc
				}
				return "XX" // DB loaded but IP unresolved
			}
		}
	}

	if path, explicit := dbPath("WAF_ASN_DB", "/geoip/ip-to-asn.mmdb"); path != "" {
		db, err := geoip.OpenASN(path)
		switch {
		case err != nil && explicit:
			slog.Error("edge: cannot open asn database; request.asn will be 0", "path", path, "error", err)
		case err != nil:
			slog.Debug("edge: no asn database at default path; request.asn disabled", "path", path)
		default:
			slog.Info("edge: asn database loaded", "path", path)
			asn = func(r *http.Request) int64 {
				return db.ASNCached(geoip.ClientIP(r))
			}
		}
	}
	return country, asn
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return n
		}
	}
	return def
}

// splitDomains parses the comma-separated EDGE_DOMAINS list, trimming entries
// and dropping empties.
func splitDomains(s string) []string {
	var out []string
	for _, d := range strings.Split(s, ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}
