package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/profiler"
	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/compress"
	"github.com/moonrhythm/parapet/pkg/header"
	"github.com/moonrhythm/parapet/pkg/host"
	"github.com/moonrhythm/parapet/pkg/logger"
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/moonrhythm/parapet/pkg/ratelimit"

	controller "github.com/moonrhythm/parapet-ingress-controller"
	"github.com/moonrhythm/parapet-ingress-controller/geoip"
	"github.com/moonrhythm/parapet-ingress-controller/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/metric"
	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
	"github.com/moonrhythm/parapet-ingress-controller/plugin"
	"github.com/moonrhythm/parapet-ingress-controller/proxy"
	"github.com/moonrhythm/parapet-ingress-controller/state"
	"github.com/moonrhythm/parapet-ingress-controller/trust"
	"github.com/moonrhythm/parapet-ingress-controller/trustcidr"
)

var version = "HEAD"

func main() {
	flag.Parse()

	httpPort := config.StringDefault("HTTP_PORT", "80")
	httpsPort := config.StringDefault("HTTPS_PORT", "443")
	podNamespace := config.String("POD_NAMESPACE")
	watchNamespace := config.StringDefault("WATCH_NAMESPACE", "")
	ingressClass := config.String("INGRESS_CLASS")
	enableProfiler := config.Bool("PROFILER")
	profilerName := config.String("PROFILER_NAME")
	disableLog := config.Bool("DISABLE_LOG")
	waitBeforeShutdown := config.DurationDefault("WAIT_BEFORE_SHUTDOWN", 30*time.Second)
	httpServerMaxHeaderBytes := config.IntDefault("HTTP_SERVER_MAX_HEADER_BYTES", 1<<14) // 16K
	loadAllCerts := config.Bool("LOAD_ALL_CERTS")
	autoH2C := config.Bool("UPSTREAM_AUTO_H2C")
	autoH2CTTL := config.DurationDefault("UPSTREAM_AUTO_H2C_TTL", 10*time.Minute)

	rateLimitEnabled := config.Bool("RATELIMIT_ENABLED")

	wafConfig := controller.WAFConfig{
		Enabled:       config.Bool("WAF_ENABLED"),
		FailClosed:    config.String("WAF_FAIL_MODE") == "closed",
		EvalTimeout:   config.DurationDefault("WAF_EVAL_TIMEOUT", 5*time.Millisecond),
		CostLimit:     uint64(config.Int("WAF_COST_LIMIT")),
		InspectBody:   int64(config.Int("WAF_INSPECT_BODY")),
		DisableMacros: config.Bool("WAF_DISABLE_MACROS"),
	}
	// GeoIP databases for the WAF. WAF_GEOIP_DB (request.country) and WAF_ASN_DB
	// (request.asn) default to the paths baked into the image; set either to a
	// custom path, or to "" to disable. A missing file at an explicitly-set path
	// is logged as an error; a missing file at the default path is a quiet no-op
	// (the DB just wasn't baked). Loading is always non-fatal.
	if wafConfig.Enabled {
		// dbPath returns (path, explicit): the env value when set ("" disables),
		// else the baked default (a missing default file is not an error).
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
				slog.Error("waf: can not open geoip database; request.country will be empty",
					"path", path, "error", err)
			case err != nil:
				slog.Debug("waf: no geoip database at default path; request.country disabled",
					"path", path)
			default:
				slog.Info("waf: geoip database loaded", "path", path)
				wafConfig.Country = func(r *http.Request) string {
					// CountryCached memoizes by client IP so repeat IPs skip the
					// mmdb lookup; semantics are identical to db.Country.
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
				slog.Error("waf: can not open asn database; request.asn will be 0",
					"path", path, "error", err)
			case err != nil:
				slog.Debug("waf: no asn database at default path; request.asn disabled",
					"path", path)
			default:
				slog.Info("waf: asn database loaded", "path", path)
				wafConfig.ASN = func(r *http.Request) int64 {
					// ASNCached memoizes by client IP so repeat IPs skip the mmdb
					// lookup and the per-call strconv.ParseInt; semantics are
					// identical to db.ASN.
					return db.ASNCached(geoip.ClientIP(r))
				}
			}
		}
	}

	hostname, _ := os.Hostname()

	if ingressClass != "" {
		controller.IngressClass = ingressClass
	}

	slog.Info("parapet-ingress-controller",
		"version", version,
		"hostname", hostname,
		"http_port", httpPort,
		"https_port", httpsPort,
		"ingress_class", controller.IngressClass,
		"pod_namespace", podNamespace,
		"watch_namespace", watchNamespace,
		"profiler", enableProfiler,
		"http_server_max_header_bytes", httpServerMaxHeaderBytes,
		"load_all_certs", loadAllCerts,
		"waf_enabled", wafConfig.Enabled,
		"ratelimit_enabled", rateLimitEnabled,
	)

	if enableProfiler {
		if profilerName == "" {
			profilerName = "parapet-ingress-controller"
		}
		err := profiler.Start(profiler.Config{
			Service:        profilerName,
			ServiceVersion: version,
			Instance:       hostname,
		})
		if err != nil {
			slog.Error("can not start profiler", "error", err)
		}
	}

	err := k8s.Init()
	if err != nil {
		slog.Error("can not init k8s", "error", err)
		os.Exit(1)
	}

	go prom.Start(":9187")

	proxy := proxy.New()
	proxy.ConfigTransport(configTransport)
	if autoH2C {
		proxy.EnableAutoH2C(autoH2CTTL)
	}

	ctrl := controller.New(watchNamespace, proxy)
	ctrl.LoadAllCerts = loadAllCerts
	ctrl.PodNamespace = podNamespace
	ctrl.WAFConfig = wafConfig
	ctrl.InitWAF()
	ctrl.RateLimitEnabled = rateLimitEnabled
	ctrl.InitRateLimit()
	ctrl.Use(plugin.InjectStateIngress)
	ctrl.Use(plugin.AllowRemote)
	if wafConfig.Enabled {
		ctrl.Use(plugin.WAFZone(ctrl.LookupZone))
	}
	ctrl.Use(plugin.RedirectHTTPS)
	ctrl.Use(plugin.InjectHSTS)
	ctrl.Use(plugin.RedirectRules)
	if rateLimitEnabled {
		// Zone rate limits run just before the per-ingress annotation limiters:
		// coarse tenant-wide limits first, then the ingress's own.
		ctrl.Use(plugin.RateLimitZone(ctrl.LookupRateLimitZone))
	}
	ctrl.Use(plugin.RateLimit)
	ctrl.Use(plugin.BodyLimit)
	ctrl.Use(plugin.UpstreamProtocol)
	ctrl.Use(plugin.UpstreamHost)
	ctrl.Use(plugin.UpstreamPath)
	ctrl.Use(plugin.OperationsTrace)
	ctrl.Use(plugin.BasicAuth)
	ctrl.Use(plugin.ForwardAuth)
	ctrl.Use(plugin.StripPrefix)
	// Watch starts below, AFTER the edge-trust readiness hook is wired — firstReload
	// reads ctrl.WaitTrustReady, so it must be installed before Watch runs.

	m := parapet.Middlewares{}
	m.Use(ctrl.Healthz())
	m.Use(host.StripPort())
	m.Use(host.ToLower())
	m.Use(metric.HostActiveTracker(ctrl.IsKnownHost))
	m.Use(hostCountryRateLimit(ctrl.IsKnownHost))
	m.Use(hostRateLimit(ctrl.IsKnownHost))

	if !disableLog {
		m.Use(logger.Stdout())
	}
	m.Use(state.Middleware(!disableLog))
	m.Use(metric.Requests(ctrl.IsKnownHost))
	m.Use(compress.Gzip())
	m.Use(compress.BrWithQuality(4))
	m.Use(compress.Zstd())
	if wafConfig.Enabled {
		// Global WAF runs just before routing: blocks are access-logged and
		// counted above, and request.host is already normalized. Per-zone WAF
		// runs inside the per-ingress chain (plugin.WAFZone).
		m.Use(ctrl.GlobalWAF())
	}
	if rateLimitEnabled {
		// Global rate limits run after the global WAF, deliberately: WAF-blocked
		// traffic never burns rate budget, and a rate-limited client can't dodge
		// the WAF's matching/metrics. (The reverse order would shed limiter
		// rejections before spending CEL evaluation on them — chosen against.)
		// Rejections here are access-logged and counted above, like WAF blocks.
		// Per-zone limits run inside the per-ingress chain (plugin.RateLimitZone).
		m.Use(ctrl.GlobalRateLimit())
	}
	// Forward the resolved GeoIP country/ASN to upstreams. Mounted only when a DB
	// is loaded (resolver non-nil); runs just before routing so the headers reach
	// the proxied request.
	if wafConfig.Country != nil || wafConfig.ASN != nil {
		m.Use(forwardGeoHeaders(wafConfig.Country, wafConfig.ASN))
	}
	m.Use(ctrl)

	cidrTrust := trustcidr.Parse(config.String("TRUST_PROXY"))

	// Edge auto-trust (CA-only mTLS). When EDGE_TRUST_CP_ENDPOINT is set, the core
	// pulls the edge CA from the control plane (GET /v1/trust-bundle, tokenless,
	// over MANDATORY verified server-TLS) and trusts any client-cert chain verified
	// to it — in addition to the static TRUST_PROXY CIDRs. See EDGE-AUTOTRUST.md.
	var trustMgr *trust.Manager
	if ep := config.String("EDGE_TRUST_CP_ENDPOINT"); ep != "" {
		mode, err := trust.ClassifyEndpoint(ep)
		if err != nil {
			slog.Error("EDGE_TRUST_CP_ENDPOINT rejected", "endpoint", ep, "error", err)
			os.Exit(1)
		}

		var tc *trust.Client
		switch mode {
		case trust.ModeHTTPS:
			if caPath := config.String("EDGE_TRUST_CP_CA"); caPath != "" {
				// Pinned CA: trust only this CA for the CP server cert (tightest).
				caPEM, err := os.ReadFile(caPath)
				if err != nil {
					// Explicitly set but unreadable is a misconfiguration — don't silently
					// downgrade to system roots; stay fatal.
					slog.Error("EDGE_TRUST_CP_CA is set but not readable", "path", caPath, "error", err)
					os.Exit(1)
				}
				tc, err = trust.NewClient(ep, caPEM)
				if err != nil {
					slog.Error("edge trust client", "error", err)
					os.Exit(1)
				}
			} else {
				// No pinned CA: verify the CP server cert against the host's system trust
				// store (the image ships ca-certificates). Real verified TLS with hostname
				// checks — weaker than pinning (any system-trusted CA could impersonate the
				// CP), so set EDGE_TRUST_CP_CA for the tightest trust on this tokenless
				// channel.
				slog.Info("edge trust: EDGE_TRUST_CP_CA unset — verifying the CP server cert against the system trust store", "endpoint", ep)
				tc = trust.NewSystemRootsClient(ep)
			}
		case trust.ModeInsecureHTTP:
			// http:// endpoint: plaintext, no in-process integrity guarantee, so say so
			// loudly (mirrors the CP's own plaintext-mode warning). Only safe when the
			// transport already provides mutual auth + encryption.
			slog.Warn("edge trust: PLAINTEXT trust channel (http:// endpoint) — the tokenless "+
				"trust-bundle has NO on-wire integrity; a MITM can inject a forged CA and forge the "+
				"ENTIRE edge fleet (spoof X-Forwarded-For, bypass WAF/rate-limits). Only run this on a "+
				"transport that already provides mutual auth + encryption (mesh/tunnel/VPC).", "endpoint", ep)
			tc = trust.NewInsecureHTTPClient(ep)
		}

		trustMgr = trust.NewManager()
		// Warm-start cache (optional): persist the last-good bundle so a restart-during-outage
		// can't resurrect a rotated-out CA via a stale CP replica. The cache seeds an
		// anti-rollback generation FLOOR; it confers NO trust until a live fetch revalidates
		// (mTLS stays CIDR-only meanwhile). See EDGE-AUTOTRUST.md "Warm-start cache".
		if cacheFile := config.String("EDGE_TRUST_CP_CACHE_FILE"); cacheFile != "" {
			maxStale := time.Duration(config.IntDefault("EDGE_TRUST_CP_MAX_STALE", 3600)) * time.Second
			trustMgr.EnableWarmStart(cacheFile, maxStale)
		}
		pollInterval := time.Duration(config.IntDefault("EDGE_TRUST_CP_POLL_INTERVAL", 300)) * time.Second
		go trustMgr.Run(context.Background(), tc, pollInterval)
		slog.Info("edge auto-trust enabled (CA-only mTLS)", "endpoint", ep)
	}

	// Edge auto-trust: gate readiness on the edge-CA pool, bounded and fail-static, so a
	// freshly-started core isn't routed edge traffic during the cold-start window — when
	// :443 sends no CertificateRequest yet and a mTLS-only edge (no CIDR cover) would stay
	// untrusted on any connection it opens until that connection recycles. The wait runs
	// after k8s preload (in firstReload), by which point the parallel trust fetch has
	// usually landed, so it is normally a no-op. EDGE_TRUST_READY_WAIT bounds it (default
	// 10s); on timeout the core reports Ready and serves CIDR-only until the bundle loads
	// (the edge converges to mTLS-trusted then). Set 0 to disable the wait (pure
	// fail-static, the pre-gate behavior). Off entirely when auto-trust is off.
	if trustMgr != nil {
		readyWait := config.DurationDefault("EDGE_TRUST_READY_WAIT", 10*time.Second)
		if readyWait < 0 {
			readyWait = 0 // negative is meaningless; normalize to "disabled" so the logging below is consistent
		}
		ctrl.WaitTrustReady = func() {
			if trustMgr.WaitReady(context.Background(), readyWait) {
				slog.Info("edge trust: CA pool loaded; reporting Ready (edge mTLS active)")
			} else if readyWait > 0 {
				slog.Warn("edge trust: CA pool not loaded within EDGE_TRUST_READY_WAIT; "+
					"reporting Ready and serving CIDR-only until the bundle loads (edge mTLS converges then)",
					"wait", readyWait)
			}
		}
	}

	// Start watching now that the readiness hook (read by firstReload) is installed.
	go ctrl.Watch()

	// The installed-once trust predicate: static CIDR OR (with auto-trust) a client
	// cert cryptographically verified to the edge CA. The verification happens in
	// the TLS handshake (ClientCAs from trustMgr), so the closure is a single
	// non-empty check — no SAN lookup, no allow-set.
	trustProxy := cidrTrust
	if trustMgr != nil {
		trustProxy = func(r *http.Request) bool {
			// Resolve the decision to ONE source, then emit exactly once (never
			// double-count). cidr takes precedence, so verified-chain undercounts a
			// dual-path edge — a verified-chain flatline after rotation is still the
			// earliest convergence-failure signal. This closure exists only when
			// trustMgr != nil, so the trust-disabled path stays free of per-request work.
			src := metric.TrustSrcNone
			if cidrTrust != nil && cidrTrust(r) {
				src = metric.TrustSrcCIDR
			} else if trustMgr.VerifyClientCert(r.TLS) {
				// An edge client cert that chains to the live edge CA, verified per
				// request. A non-edge client cert (e.g. Cloudflare Authenticated Origin
				// Pulls) simply isn't trusted here — the handshake was never aborted for
				// it — so it falls through to the CIDR branch above.
				src = metric.TrustSrcVerifiedChain
			}
			metric.TrustSource(src)
			return src != metric.TrustSrcNone
		}
	}

	var wg sync.WaitGroup

	// http
	{
		s := &parapet.Server{
			Addr:               ":" + httpPort,
			MaxHeaderBytes:     httpServerMaxHeaderBytes,
			TrustProxy:         trustProxy,
			IdleTimeout:        60 * time.Second,
			TCPKeepAlivePeriod: 1 * time.Minute,
			GraceTimeout:       1 * time.Minute,
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
			err := s.ListenAndServe()
			if err != nil {
				slog.Error("can not start http server", "error", err)
				os.Exit(1)
			}
		}()
	}

	// https
	if httpsPort != "" {
		cert, err := parapet.GenerateSelfSignCertificate(parapet.SelfSign{
			CommonName: "parapet-ingress-controller",
		})
		if err != nil {
			slog.Error("can not generate self sign certificate", "error", err)
			os.Exit(1)
		}

		tlsConfig := &tls.Config{
			MinVersion:     tls.VersionTLS12,
			Certificates:   []tls.Certificate{cert},
			GetCertificate: ctrl.GetCertificate,
		}
		// Edge auto-trust: verify an optional edge client cert against the
		// hot-reloaded edge-CA pool (CA-only trust). The SNI cert table is untouched.
		// See trust.Manager.ServerTLSConfig for the cold-start / per-handshake logic.
		if trustMgr != nil {
			tlsConfig = trustMgr.ServerTLSConfig(ctrl.GetCertificate, []tls.Certificate{cert})
		}

		s := &parapet.Server{
			Addr:               ":" + httpsPort,
			MaxHeaderBytes:     httpServerMaxHeaderBytes,
			TrustProxy:         trustProxy,
			IdleTimeout:        320 * time.Second,
			TCPKeepAlivePeriod: 1 * time.Minute,
			GraceTimeout:       1 * time.Minute,
			WaitBeforeShutdown: waitBeforeShutdown,
			Handler:            http.NotFoundHandler(),
			ShareProtoSlice:    true,
			TLSConfig:          tlsConfig,
		}
		prom.Connections(s)
		prom.Networks(s)

		s.Use(m)

		wg.Add(1)
		go func() {
			defer wg.Done()
			err = s.ListenAndServe()
			if err != nil {
				slog.Error("can not start https server", "error", err)
				os.Exit(1)
			}
		}()
	}

	wg.Wait()
}

func configTransport(tr *http.Transport) {
	tr.MaxConnsPerHost = config.IntDefault(
		"TR_MAX_CONNS_PER_HOST", tr.MaxConnsPerHost)
	tr.MaxIdleConnsPerHost = config.IntDefault(
		"TR_MAX_IDLE_CONNS_PER_HOST", tr.MaxIdleConnsPerHost)
}

// forwardGeoHeaders sets X-Forwarded-Country / X-Forwarded-ASN on each request
// from the GeoIP resolvers, so upstreams get the proxy's authoritative GeoIP
// values for the same client IP the WAF uses. Each header is set — overwriting
// any client-supplied value, so it can't be spoofed — only when its resolver is
// non-nil (the DB is loaded); an unplaceable IP yields "XX" / 0. A nil resolver
// leaves the corresponding header untouched.
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

// hostRateLimit protects from unresponsive upstreams by limit concurrent requests to the same host.
func hostRateLimit(isKnownHost func(host string) bool) parapet.Middleware {
	concurrentCapacity := config.Int("HOST_CONCURRENT_CAPACITY") // concurrent requests
	concurrentSize := config.Int("HOST_CONCURRENT_SIZE")         // queue size

	if concurrentCapacity <= 0 {
		return nil
	}

	keyFromRequest := func(r *http.Request) string {
		return r.Host
	}

	exceededHandler := func(w http.ResponseWriter, r *http.Request, _ time.Duration) {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		metric.HostRatelimitRequest(metric.HostLabel(r.Host, isKnownHost))
		metric.RejectedRequest("host_limit")
	}

	// Decision counter (allowed|limited) — the limited side complements the
	// existing host-limit rejection metrics with an allowed denominator.
	rlObserve := observe.RateLimit("host")

	if concurrentSize > 0 {
		slog.Info("setting up host rate limit", "strategy", "ConcurrentQueue", "capacity", concurrentCapacity, "size", concurrentSize)
		return ratelimit.RateLimiter{
			Name:    "host",
			Observe: rlObserve,
			Strategy: &ratelimit.ConcurrentQueueStrategy{
				Capacity: concurrentCapacity,
				Size:     concurrentSize,
			},
			Key:                  keyFromRequest,
			ExceededHandler:      exceededHandler,
			ReleaseOnWriteHeader: true,
			ReleaseOnHijacked:    true,
		}
	}

	slog.Info("setting up host rate limit", "strategy", "Concurrent", "capacity", concurrentCapacity)
	return ratelimit.RateLimiter{
		Name:    "host",
		Observe: rlObserve,
		Strategy: &ratelimit.ConcurrentStrategy{
			Capacity: concurrentCapacity,
		},
		Key:                  keyFromRequest,
		ExceededHandler:      exceededHandler,
		ReleaseOnWriteHeader: true,
		ReleaseOnHijacked:    true,
	}
}

// hostCountryRateLimit protects from unresponsive upstreams by limit concurrent requests to the same host and country.
func hostCountryRateLimit(isKnownHost func(host string) bool) parapet.Middleware {
	concurrentCapacity := config.Int("HOST_COUNTRY_CONCURRENT_CAPACITY") // concurrent requests
	concurrentSize := config.Int("HOST_COUNTRY_CONCURRENT_SIZE")         // queue size
	countryHeaderRaw := strings.TrimSpace(config.String("HOST_COUNTRY_HEADER"))

	if concurrentCapacity <= 0 {
		return nil
	}
	if countryHeaderRaw == "" {
		return nil
	}

	var countryHeaders []string
	for _, h := range strings.Split(countryHeaderRaw, ",") {
		if h = strings.TrimSpace(h); h != "" {
			countryHeaders = append(countryHeaders, http.CanonicalHeaderKey(h))
		}
	}
	if len(countryHeaders) == 0 {
		return nil
	}

	keyFromRequest := func(r *http.Request) string {
		country := ""
		for _, h := range countryHeaders {
			if v := header.Get(r.Header, h); v != "" {
				country = v
				break
			}
		}
		if country == "" {
			country = "XX"
		}
		return r.Host + "|" + country
	}

	exceededHandler := func(w http.ResponseWriter, r *http.Request, _ time.Duration) {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		metric.HostRatelimitRequest(metric.HostLabel(r.Host, isKnownHost))
		metric.RejectedRequest("host_limit")
	}

	rlObserve := observe.RateLimit("host-country")

	if concurrentSize > 0 {
		slog.Info("setting up host country rate limit", "strategy", "ConcurrentQueue", "capacity", concurrentCapacity, "size", concurrentSize)
		return ratelimit.RateLimiter{
			Name:    "host-country",
			Observe: rlObserve,
			Strategy: &ratelimit.ConcurrentQueueStrategy{
				Capacity: concurrentCapacity,
				Size:     concurrentSize,
			},
			Key:                  keyFromRequest,
			ExceededHandler:      exceededHandler,
			ReleaseOnWriteHeader: true,
			ReleaseOnHijacked:    true,
		}
	}

	slog.Info("setting up host country rate limit", "strategy", "Concurrent", "capacity", concurrentCapacity)
	return ratelimit.RateLimiter{
		Name:    "host-country",
		Observe: rlObserve,
		Strategy: &ratelimit.ConcurrentStrategy{
			Capacity: concurrentCapacity,
		},
		Key:                  keyFromRequest,
		ExceededHandler:      exceededHandler,
		ReleaseOnWriteHeader: true,
		ReleaseOnHijacked:    true,
	}
}
