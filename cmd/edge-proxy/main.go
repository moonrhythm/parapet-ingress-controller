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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/moonrhythm/parapet/pkg/healthz"
	"github.com/moonrhythm/parapet/pkg/host"
	"github.com/moonrhythm/parapet/pkg/logger"
	"github.com/moonrhythm/parapet/pkg/prom"

	"github.com/moonrhythm/parapet-ingress-controller/edge"
	"github.com/moonrhythm/parapet-ingress-controller/geoip"
	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
	"github.com/moonrhythm/parapet-ingress-controller/trustcidr"
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
	dataplaneMTLS := envOr("EDGE_DATAPLANE_MTLS", "false") == "true"
	if dataplaneMTLS && !upstreamTLS {
		slog.Error("EDGE_DATAPLANE_MTLS=true requires EDGE_UPSTREAM_TLS=true (a client cert can only ride TLS)")
		os.Exit(1)
	}
	// EDGE_ID is the edge's STABLE logical identity stamped on every convergence metric
	// (the OLD-drop interlock joins per-edge by it). With data-plane mTLS it MUST be set
	// and MUST match this edge's CP token id, or the per-edge join silently can't find
	// the edge (it would either block forever or, worse, let a partitioned edge be
	// shadowed). Without mTLS, convergence is moot — default to the hostname.
	edgeID := os.Getenv("EDGE_ID")
	if dataplaneMTLS && edgeID == "" {
		slog.Error("EDGE_ID is required with EDGE_DATAPLANE_MTLS=true (it must match this edge's CP token id; the convergence interlock joins on it)")
		os.Exit(1)
	}
	if edgeID == "" {
		edgeID, _ = os.Hostname()
	}
	edge.SetEdgeID(edgeID)
	refreshInterval := time.Duration(envInt64("EDGE_REFRESH_INTERVAL", 300)) * time.Second
	if refreshInterval <= 0 { // a 0/negative value would panic time.NewTicker
		refreshInterval = 300 * time.Second
	}
	wafEnabled := envOr("EDGE_WAF_ENABLED", "false") == "true"
	disableLog := envOr("DISABLE_LOG", "false") == "true"
	waitBeforeShutdown := time.Duration(envInt64("WAIT_BEFORE_SHUTDOWN", 30)) * time.Second
	domains := splitDomains(os.Getenv("EDGE_DOMAINS"))
	serveAll := len(domains) == 0

	// TRUST_PROXY mirrors the controller (same spec: true/false/CIDRs +
	// cloudflare/google/bunny). Default "" → nil → the edge distrusts every
	// upstream and overwrites X-Forwarded-* with the true peer (first-hop posture).
	// Set it when the edge sits behind another L7 proxy (e.g. TRUST_PROXY=cloudflare)
	// so the real client IP from the inbound X-Forwarded-For flows through to the
	// edge WAF, GeoIP/ASN, access log, and the upstream hop. See EDGE.md.
	trustProxySpec := envOr("TRUST_PROXY", "")
	trustProxy := trustcidr.Parse(trustProxySpec)

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
		"trust_proxy", trustProxySpec,
		"refresh_interval", refreshInterval,
	)

	cp, err := edge.NewCpClient(cpEndpoint, cpToken, caPEM)
	if err != nil {
		slog.Error("edge: cannot init control-plane client", "error", err)
		os.Exit(1)
	}
	store := edge.NewCertStore()

	ctx := context.Background()

	// Optional data-plane mTLS: fetch a CP-issued client cert (CA-only trust), hold it
	// in memory (never on disk), and present it on the re-encrypt hop. The re-mint
	// coordinator owns every re-mint path (proactive on a ca_id flip observed via the
	// /v1/certs poll, reactive on a core cert-reject, timer on remaining-life). It is
	// built EARLY so it threads into the cert/WAF refresh loops as the force-re-mint
	// observer; nil when mTLS is off (every coord call is a no-op).
	var clientCertStore *edge.ClientCertStore
	var remintCoord *edge.RemintCoordinator
	if dataplaneMTLS {
		clientCertStore = edge.NewClientCertStore()
		remintCoord = edge.NewRemintCoordinator(cp, clientCertStore, edge.RemintConfig{
			Jitter:        time.Duration(envInt64("EDGE_CLIENTCERT_REMINT_JITTER", 60)) * time.Second,
			BackoffBase:   time.Duration(envInt64("EDGE_CLIENTCERT_REMINT_BACKOFF_BASE", 2)) * time.Second,
			BackoffMax:    refreshInterval,
			Cooldown:      time.Duration(envInt64("EDGE_CLIENTCERT_REMINT_COOLDOWN", int64(5*refreshInterval/time.Second))) * time.Second,
			BreakerK:      int(envInt64("EDGE_CLIENTCERT_REMINT_BREAKER_K", 3)),
			ProactiveJ:    int(envInt64("EDGE_CLIENTCERT_REMINT_PROACTIVE_J", 5)),
			RenewFraction: envFloat("EDGE_CLIENTCERT_RENEW_REMAINING_FRACTION", 0.66),
		})
	}

	if serveAll {
		// On a handshake for an SNI not held, fetch it from the control plane (the
		// handshake blocks on it); the CP's per-token authz still gates which SNIs
		// resolve. The periodic refresh keeps on-demand domains rotated.
		store.ConfigureOnDemand(
			time.Duration(envInt64("EDGE_ONDEMAND_NEG_TTL", 30))*time.Second,
			int(envInt64("EDGE_ONDEMAND_MAX_INFLIGHT", 32)),
		)
		store.SetOnDemand(func(sni string) { edge.RefreshCertOnce(cp, store, sni, remintCoord) })
		slog.Info("edge: EDGE_DOMAINS empty — serving ALL domains (certs fetched on demand)")
	} else {
		loaded := edge.RefreshCertsAll(cp, store, domains, remintCoord)
		slog.Info("edge: initial cert load", "loaded", loaded, "total", len(domains))
	}
	go edge.RunCertRefresh(ctx, cp, store, domains, refreshInterval, remintCoord)

	if dataplaneMTLS {
		// Startup mint is direct + UN-jittered (readiness needs it fast); the periodic
		// loops are jittered so a simultaneous fleet restart doesn't thunder. A
		// boot-during-overlap edge that freezes at a stale ca_id gets a proactive
		// recheck within one interval via the jittered first cert-refresh/trust-bundle tick.
		edge.RefreshEdgeCertOnce(cp, clientCertStore, "timer") // best-effort; fail-static
		go edge.RunEdgeCertRefresh(ctx, remintCoord, refreshInterval)
		slog.Info("edge: data-plane mTLS enabled (CP-issued client cert)")
	}

	// Optional edge WAF (early-drop; parapet stays authoritative). GeoIP/ASN are
	// resolved from the client IP — the true peer when the edge is the first hop,
	// or the inbound X-Forwarded-For client when TRUST_PROXY trusts the front proxy.
	var ewaf *edge.EdgeWAF
	var country func(*http.Request) string
	var asn func(*http.Request) int64
	if wafEnabled {
		country, asn = loadGeoResolvers()
		ewaf = edge.NewEdgeWAF(country, asn)
		edge.RefreshWafOnce(cp, ewaf, remintCoord)
		go edge.RunWafRefresh(ctx, cp, ewaf, refreshInterval, remintCoord)
	}

	// Optional response cache (off by default), from parapet/pkg/cache. The
	// backend is disk (default; survives restarts, bounded by on-disk bytes) or
	// memory (EDGE_CACHE_BACKEND=memory; bodies in RAM, lost on restart).
	var respCache *cache.Cache
	var purgeTable *edge.PurgeTable
	var purgeStorage cache.Storage // the live backend, for the reaper's Range sweep
	if envOr("EDGE_CACHE_ENABLED", "false") == "true" {
		maxSize := envInt64("EDGE_CACHE_MAX_SIZE", 1<<30)
		maxFile := envInt64("EDGE_CACHE_MAX_FILE_SIZE", 8<<20)
		var storage cache.Storage
		var purgeStatePath string // disk backend persists purge state alongside the cache
		switch envOr("EDGE_CACHE_BACKEND", "disk") {
		case "memory":
			storage = cache.NewMemory(maxSize)
			slog.Info("edge cache enabled (in-memory)", "max_size", maxSize, "max_file", maxFile)
		default: // disk
			dir := envOr("EDGE_CACHE_DIR", "/var/cache/parapet-edge")
			d, err := cache.NewDisk(dir, maxSize)
			if err != nil {
				slog.Error("edge cache: cannot init cache dir; caching disabled", "dir", dir, "error", err)
			} else {
				storage = d
				purgeStatePath = filepath.Join(dir, "purge-state")
				slog.Info("edge cache enabled (disk-backed)", "dir", dir, "max_size", maxSize, "max_file", maxFile)
			}
		}
		if storage != nil {
			// Cache outcomes: bounded prom counters (no host label — serve-all
			// means r.Host is unbounded) + a cacheStatus access-log field
			// (no-op under DISABLE_LOG — no logger record to set).
			cacheMetrics := observe.CacheResult()
			opts := cache.Options{
				MaxFileSize: maxFile,
				OnResult: func(r *http.Request, info cache.ResultInfo) {
					cacheMetrics(r, info)
					cache.LogResult(r, info)
				},
			}
			// Cache-purge: an invalidation table fed from the control plane gates each
			// hit (parapet's Options.InvalidatedAfter). On by default with the cache; the
			// poll loop fail-statics if the CP isn't distributing purges. The table
			// persists alongside the disk cache (in-memory backend keeps no state).
			if envOr("EDGE_CACHE_PURGE_ENABLED", "true") == "true" {
				pt, err := edge.NewPurgeTable(purgeStatePath, int(envInt64("EDGE_CACHE_PURGE_MAX_RECORDS", 0)))
				if err != nil {
					slog.Warn("edge cache: purge state load failed; starting from a clean table", "error", err)
				}
				purgeTable = pt
				purgeStorage = storage
				opts.InvalidatedAfter = purgeTable.InvalidatedAfter
			}
			respCache = cache.New(storage, opts)
		}
	}
	// Start the purge poll loop + reaper once when the table is live.
	if purgeTable != nil {
		purgeInterval := time.Duration(envInt64("EDGE_CACHE_PURGE_POLL_INTERVAL", 10)) * time.Second
		edge.RefreshPurgeOnce(cp, purgeTable) // best-effort initial sync; fail-static
		go edge.RunPurgeRefresh(ctx, cp, purgeTable, purgeInterval)
		// The reaper physically reclaims invalidated entries off the serving path (the
		// lazy lookup gate already guarantees correctness; this is just reclamation).
		// Housekeeping cadence, jittered.
		sweepInterval := time.Duration(envInt64("EDGE_CACHE_PURGE_SWEEP_INTERVAL", 300)) * time.Second
		go edge.RunReaper(ctx, purgeStorage, purgeTable, sweepInterval)
		slog.Info("edge cache: purge polling enabled", "poll_interval", purgeInterval, "sweep_interval", sweepInterval)
	}

	var getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	var onCertReject func()
	if clientCertStore != nil {
		getClientCert = clientCertStore.GetClientCertificate
		// Reactive force-re-mint floor: a core cert-reject in the re-encrypt handshake
		// fires a (non-blocking) reactive re-mint. nil when mTLS is off.
		onCertReject = func() { remintCoord.Trigger("reactive") }
	}
	forwarder := edge.NewForwarder(upstreamAddr, upstreamTLS, upstreamSNI, getClientCert, onCertReject)

	if metricsListen != "" {
		go func() {
			if err := prom.Start(metricsListen); err != nil {
				slog.Error("edge: metrics listener failed", "error", err)
			}
		}()
	}

	health := healthz.New()
	health.SetReady(false) // healthz defaults to ready; gate it on a usable cert below

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
		m.Use(respCache)
	}
	m.Use(forwarder)

	// Readiness: green once the edge has a usable cert (so the LB doesn't send
	// traffic to an edge that would only serve the self-signed fallback). In
	// serve-all mode there is no pre-fetch, so it's ready immediately (certs are
	// fetched on demand). If the initial load failed (control plane down), a
	// background poll flips readiness once the periodic refresh lands a cert.
	// Readiness needs a usable public cert AND, when data-plane mTLS is on, a loaded
	// client cert (so the LB never routes to an edge that would be untrusted by the
	// core — fail-closed; serve-all does not bypass the client-cert gate).
	edgeReady := func() bool {
		if dataplaneMTLS && !clientCertStore.Loaded() {
			return false
		}
		return serveAll || store.Loaded()
	}
	if edgeReady() {
		health.SetReady(true)
	} else {
		go func() {
			for !edgeReady() {
				time.Sleep(2 * time.Second)
			}
			health.SetReady(true)
			slog.Info("edge: ready (certs loaded)")
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
			TrustProxy:         trustProxy,
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
			TrustProxy:         trustProxy,
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

func envFloat(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok {
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return f
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
