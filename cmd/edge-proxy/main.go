// Command edge-proxy is the out-of-cluster parapet edge proxy (Go). It
// terminates public TLS locally with a cert+key fetched from the in-cluster edge
// control plane, runs the global + zone WAF as an early-drop layer, optionally
// caches responses on disk, and forwards to the in-cluster parapet with the
// X-Forwarded-* headers parapet trusts. See ../../EDGE.md.
//
// The edge reuses the controller's cert/wafrule/geoip packages and
// parapet/pkg/waf (the CEL engine), so the edge WAF blocks identically to
// parapet — which remains authoritative.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/moonrhythm/parapet/pkg/healthz"
	"github.com/moonrhythm/parapet/pkg/host"
	"github.com/moonrhythm/parapet/pkg/logger"
	"github.com/moonrhythm/parapet/pkg/prom"

	"github.com/moonrhythm/parapet-ingress-controller/edge"
	"github.com/moonrhythm/parapet-ingress-controller/geoip"
	"github.com/moonrhythm/parapet-ingress-controller/trustcidr"
	"github.com/moonrhythm/parapet-ingress-controller/wsh2"
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
		// An explicit CA pin must never fail open to system roots: this channel
		// carries the bearer token and TLS private keys, so an unreadable file is
		// fatal rather than a silent fall-back.
		b, err := os.ReadFile(p)
		if err != nil {
			slog.Error("edge: cannot read EDGE_CP_CA", "path", p, "error", err)
			os.Exit(1)
		}
		caPEM = b
	}
	upstreamAddr := envOr("EDGE_UPSTREAM_ADDR", "parapet:80")
	upstreamTLS := envOr("EDGE_UPSTREAM_TLS", "false") == "true"
	upstreamSNI := envOr("EDGE_UPSTREAM_SNI", "")
	// Default on: h2c on the plaintext hop, ALPN h2 (HTTP/1.1 fallback) on re-encrypt.
	// Set EDGE_UPSTREAM_HTTP2=false to force HTTP/1.1 — e.g. a core that predates H2C
	// on :80, or an L4 in front of :443 that can't ALPN.
	upstreamHTTP2 := envOr("EDGE_UPSTREAM_HTTP2", "true") == "true"
	// Tunnel client WebSocket upgrades over a single multiplexed h2/h2c stream to
	// the core (RFC 8441 extended CONNECT) instead of one dedicated HTTP/1.1
	// connection each. Default on (opt-out): against a core that doesn't advertise
	// the capability the attempt fails pre-flight with zero wire cost and the
	// request falls back to HTTP/1.1, so the flag being on is safe at any skew.
	// Only meaningful when the upstream hop is h2; with h2 off it is a no-op (WS
	// rides h1 as today) — warn if it was set explicitly.
	upstreamWSH2 := envOr("EDGE_UPSTREAM_WS_H2", "true") == "true"
	if upstreamWSH2 && !upstreamHTTP2 {
		slog.Warn("EDGE_UPSTREAM_WS_H2 is ignored when EDGE_UPSTREAM_HTTP2=false; WebSocket rides HTTP/1.1")
		upstreamWSH2 = false
	}

	// Accepting WS-over-HTTP/2 (RFC 8441 extended CONNECT) from clients on the
	// public :443 listener is gated by the real GODEBUG env var, read by the h2
	// server in package init(). A user-supplied GODEBUG in the pod spec REPLACES the
	// Dockerfile's ENV entirely, silently disabling it — so verify at startup and
	// warn (not fatal: h1 WebSocket is unaffected; clients just can't use WS-over-h2).
	if !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
		slog.Warn("WS-over-HTTP/2 acceptance DISABLED: GODEBUG does not contain http2xconnect=1 " +
			"(a user-supplied GODEBUG replaces the image default); the edge will not accept " +
			"WS-over-h2 from clients; h1 WebSocket unaffected")
	}
	// Per-host connection ceiling to the core (mirrors the controller's
	// TR_MAX_CONNS_PER_HOST / TR_MAX_IDLE_CONNS_PER_HOST). MAX_CONNS_PER_HOST=0
	// (default) leaves connections unbounded; MAX_IDLE_CONNS_PER_HOST=0 falls back
	// to parapet's default idle pool (32). See edge.ForwarderTuning for which paths
	// the hard ceiling applies to (HTTP/1.1 + re-encrypt h2; the multiplexed h2c
	// stream path is inherently low-connection and not connection-capped).
	upstreamTuning := edge.ForwarderTuning{
		MaxConnsPerHost:     int(envInt64("EDGE_UPSTREAM_MAX_CONNS_PER_HOST", 0)),
		MaxIdleConnsPerHost: int(envInt64("EDGE_UPSTREAM_MAX_IDLE_CONNS_PER_HOST", 0)),
	}
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
	corazaEnabled := envOr("EDGE_CORAZA_ENABLED", "false") == "true"
	ratelimitEnabled := envOr("EDGE_RATELIMIT_ENABLED", "false") == "true"
	cacheEnabled := envOr("EDGE_CACHE_ENABLED", "false") == "true"
	cacheOverrideEnabled := envOr("EDGE_CACHE_OVERRIDE_ENABLED", "false") == "true"
	if cacheOverrideEnabled && !cacheEnabled {
		// Overrides only steer the cache; with no cache there is nothing to steer.
		slog.Warn("EDGE_CACHE_OVERRIDE_ENABLED=true has no effect without EDGE_CACHE_ENABLED=true; ignoring")
		cacheOverrideEnabled = false
	}
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
		"upstream_http2", upstreamHTTP2,
		"serve_all", serveAll,
		"domains", len(domains),
		"waf_enabled", wafEnabled,
		"coraza_enabled", corazaEnabled,
		"ratelimit_enabled", ratelimitEnabled,
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

	// Change-notification stream (GET /v1/events): pokes the refresh loops the
	// moment the CP's stores change, so updates propagate in ~seconds instead of
	// one EDGE_REFRESH_INTERVAL. Pure accelerator — the jittered poll loops stay
	// as the correctness floor, and an old CP (404) just means pure polling.
	// Buffered(1) pokes coalesce; each loop consumes its own channel, keeping
	// refreshes single-flight per resource.
	eventsEnabled := envOr("EDGE_EVENTS_ENABLED", "true") == "true"
	var pokes edge.EventPokes
	var certPoke, wafPoke, corazaPoke, rlPoke, hostsPoke, purgePoke chan struct{}
	if eventsEnabled {
		certPoke = make(chan struct{}, 1)
		pokes.Certs = certPoke
	}

	// Known-host set (GET /v1/hosts) — the request metric's host oracle. Always
	// fetched (the metric is always mounted), independent of WAF/ratelimit;
	// fail-static, and a 404 from a CP without the endpoint just leaves the metric
	// collapsing every host to "other".
	edgeHosts := edge.NewEdgeHosts()
	edge.RefreshHostsOnce(cp, edgeHosts)
	if eventsEnabled {
		hostsPoke = make(chan struct{}, 1)
		pokes.Hosts = hostsPoke
	}
	go edge.RunHostsRefresh(ctx, cp, edgeHosts, refreshInterval, hostsPoke)

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
	go edge.RunCertRefresh(ctx, cp, store, domains, refreshInterval, remintCoord, certPoke)

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
	// The resolvers load when EITHER feature needs them (mirrors the controller):
	// the WAF for request.country/request.asn, the rate limiter for its
	// country/asn keys (SetLimits rejects geo-keyed limits when nil).
	var ewaf *edge.EdgeWAF
	var country func(*http.Request) string
	var asn func(*http.Request) int64
	if wafEnabled || ratelimitEnabled || cacheOverrideEnabled {
		country, asn = loadGeoResolvers()
	}
	if wafEnabled {
		ewaf = edge.NewEdgeWAF(country, asn)
		edge.RefreshWafOnce(cp, ewaf, remintCoord)
		if eventsEnabled {
			wafPoke = make(chan struct{}, 1)
			pokes.WAF = wafPoke
		}
		go edge.RunWafRefresh(ctx, cp, ewaf, refreshInterval, remintCoord, wafPoke)
	}

	// Optional edge Coraza (SecLang/CRS early-drop layer; parapet stays
	// authoritative — defense-in-depth, no validated-proxy claim). Independent of
	// the CEL WAF: either can run alone. RootFS is the embedded OWASP CRS so a
	// ruleset can `Include @crs-setup.conf.example` + `Include @owasp_crs/*.conf`
	// (the bare forms don't resolve — Include globs only on '*').
	var ecoraza *edge.EdgeCoraza
	if corazaEnabled {
		ecoraza = edge.NewEdgeCoraza(coreruleset.FS, int(envInt64("EDGE_CORAZA_REQUEST_BODY_LIMIT", 0)))
		edge.RefreshCorazaOnce(cp, ecoraza)
		if eventsEnabled {
			corazaPoke = make(chan struct{}, 1)
			pokes.Coraza = corazaPoke
		}
		go edge.RunCorazaRefresh(ctx, cp, ecoraza, refreshInterval, corazaPoke)
	}

	// Optional edge rate limiting (ConfigMap-driven global + zone sets fetched
	// from the control plane). Counters are per edge, exactly as the
	// controller's are per pod; the core still enforces its own limits.
	var erl *edge.EdgeRateLimit
	if ratelimitEnabled {
		erl = edge.NewEdgeRateLimit(country, asn)
		edge.RefreshRateLimitOnce(cp, erl)
		if eventsEnabled {
			rlPoke = make(chan struct{}, 1)
			pokes.RateLimit = rlPoke
		}
		go edge.RunRateLimitRefresh(ctx, cp, erl, refreshInterval, rlPoke)
	}

	// Optional cache overrides (ConfigMap-driven global + zone sets fetched from
	// the control plane). They feed the response cache's two per-request hooks
	// (Cacheable for bypass rules, Override for force rules); wired into the cache
	// Options below. Requires EDGE_CACHE_ENABLED (validated above).
	var eco *edge.EdgeCacheOverride
	if cacheOverrideEnabled {
		eco = edge.NewEdgeCacheOverride(country, asn)
		edge.RefreshCacheOverrideOnce(cp, eco)
		var cachePoke chan struct{}
		if eventsEnabled {
			cachePoke = make(chan struct{}, 1)
			pokes.Cache = cachePoke
		}
		go edge.RunCacheOverrideRefresh(ctx, cp, eco, refreshInterval, cachePoke)
	}

	// Optional response cache (off by default), from parapet/pkg/cache. The
	// backend is disk (default; survives restarts, bounded by on-disk bytes) or
	// memory (EDGE_CACHE_BACKEND=memory; bodies in RAM, lost on restart).
	var respCache *cache.Cache
	var purgeTable *edge.PurgeTable
	var purgeStorage cache.Storage // the live backend, for the reaper's Range sweep
	if cacheEnabled {
		maxSize := envBytes("EDGE_CACHE_MAX_SIZE", 1<<30)
		maxFile := envBytes("EDGE_CACHE_MAX_FILE_SIZE", 8<<20)
		var storage cache.Storage
		var purgeStatePath string // disk backend persists purge state alongside the cache
		var cacheDir string       // non-empty only for the disk backend (storage + disk metrics)
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
				cacheDir = dir
				purgeStatePath = filepath.Join(dir, "purge-state")
				slog.Info("edge cache enabled (disk-backed)", "dir", dir, "max_size", maxSize, "max_file", maxFile)
			}
		}
		if storage != nil {
			// Capacity + volume gauges (parapet_cache_storage_* / parapet_cache_disk_*).
			// Registered only when the cache is live so a cache-off edge stays quiet.
			edge.RegisterCacheStorageMetrics(storage, maxSize, cacheDir)
			// Cache outcomes: the host-bounded parapet_cache_total{host,result,
			// edge_id} counter (host collapsed to "other" off the knownHost oracle,
			// the same serve-all bounding parapet_requests uses, so the per-project
			// usage pipeline can attribute outcomes by host) + a cacheStatus
			// access-log field (no-op under DISABLE_LOG — no logger record to set).
			cacheMetrics := edge.CacheTotal(edgeHosts.IsKnownHost)
			opts := cache.Options{
				MaxFileSize: maxFile,
				// Cache GET responses that arrive chunked with no Content-Length —
				// on-the-fly-compressed assets (gzip/br/zstd) are the common case, and
				// without this they're permanently uncacheable. Safe here: the edge
				// forwarder is httputil.ReverseProxy, which panics http.ErrAbortHandler
				// on a truncated upstream body, so a partial body is never committed
				// (the cap is still enforced mid-stream, SSE is never buffered). On by
				// default; EDGE_CACHE_CHUNKED=false reverts to Content-Length-only.
				CacheChunked: envOr("EDGE_CACHE_CHUNKED", "true") == "true",
				OnResult: func(r *http.Request, info cache.ResultInfo) {
					cacheMetrics(r, info)
					cache.LogResult(r, info)
				},
			}
			// Fleet-wide RFC 5861 stale serving for honor-origin entries that lack the
			// directive (independent of overrides; an explicit response directive or a
			// per-rule stale_* still wins). 0 forces nothing.
			opts.DefaultStaleWhileRevalidate = time.Duration(envInt64("EDGE_CACHE_DEFAULT_SWR", 0)) * time.Second
			opts.DefaultStaleIfError = time.Duration(envInt64("EDGE_CACHE_DEFAULT_SIE", 0)) * time.Second
			// Cache overrides drive the two per-request decision hooks: Cacheable
			// (bypass rules) and Override (force rules). nil when EDGE_CACHE_OVERRIDE_ENABLED
			// is off, leaving the cache strictly honor-origin.
			if eco != nil {
				opts.Cacheable = eco.Cacheable
				opts.Override = eco.Override
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
		if eventsEnabled {
			purgePoke = make(chan struct{}, 1)
			pokes.Purges = purgePoke
		}
		go edge.RunPurgeRefresh(ctx, cp, purgeTable, purgeInterval, purgePoke)
		// The reaper physically reclaims invalidated entries off the serving path (the
		// lazy lookup gate already guarantees correctness; this is just reclamation).
		// Housekeeping cadence, jittered.
		sweepInterval := time.Duration(envInt64("EDGE_CACHE_PURGE_SWEEP_INTERVAL", 300)) * time.Second
		go edge.RunReaper(ctx, purgeStorage, purgeTable, sweepInterval)
		slog.Info("edge cache: purge polling enabled", "poll_interval", purgeInterval, "sweep_interval", sweepInterval)
	}

	// All pokes are wired — subscribe to the CP's change stream. An old CP (no
	// /v1/events) degrades to pure polling with an occasional re-probe.
	if eventsEnabled {
		go edge.RunEvents(ctx, cp, pokes)
		slog.Info("edge: change-event stream enabled")
	}

	var getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	var onCertReject func()
	if clientCertStore != nil {
		getClientCert = clientCertStore.GetClientCertificate
		// Reactive force-re-mint floor: a core cert-reject in the re-encrypt handshake
		// fires a (non-blocking) reactive re-mint. nil when mTLS is off.
		onCertReject = func() { remintCoord.Trigger("reactive") }
	}
	forwarder := edge.NewForwarder(upstreamAddr, upstreamTLS, upstreamHTTP2, upstreamSNI, upstreamTuning, getClientCert, onCertReject, upstreamWSH2)

	if metricsListen != "" {
		go func() {
			if err := prom.Start(metricsListen); err != nil {
				slog.Error("edge: metrics listener failed", "error", err)
			}
		}()
	}

	// Opt-in metrics push: the full registry is pushed to the control plane so an
	// in-cluster Prometheus scrapes the CP's /metrics instead of reaching every
	// out-of-cluster edge. EDGE_INSTANCE_ID disambiguates replicas that share one
	// EDGE_ID; the CP labels every pushed series with (edge_id, edge_instance).
	if pushInterval := time.Duration(envInt64("EDGE_METRICS_PUSH_INTERVAL", 0)) * time.Second; pushInterval > 0 {
		instance := envOr("EDGE_INSTANCE_ID", "")
		if instance == "" {
			instance, _ = os.Hostname()
		}
		if instance == "" {
			instance = "unknown"
		}
		go edge.RunMetricsPush(ctx, cp, instance, pushInterval)
		slog.Info("edge: metrics push enabled", "interval", pushInterval, "instance", instance)
	}

	health := healthz.New()
	health.SetReady(false) // healthz defaults to ready; gate it on a usable cert below

	// Shared middleware chain (both listeners use it). Order mirrors the
	// controller: host normalization, then WAF (global, then host-bound zone)
	// before forwarding; the cache wraps the forwarder; X-Forwarded-Country/-ASN
	// are set just before forwarding.
	m := parapet.Middlewares{}
	// First in the chain, unconditional: rewrite a client's RFC 8441 extended
	// CONNECT WebSocket handshake into the h1-upgrade shape the rest of the chain
	// (WAF/Coraza/rate limits/cache/forward) understands, so h1 and h2 WebSocket
	// handshakes behave identically. A non-extended-CONNECT request pays only the
	// two header checks. onBadProtocol is nil — a non-websocket :protocol is a
	// malformed-client 501, not an edge metric.
	m.Use(parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return wsh2.NormalizeHandler(h, nil)
	}))
	m.Use(health)
	m.Use(host.StripPort())
	m.Use(host.ToLower())
	// Per-request counter (parapet_requests{host,status,method,edge_id}); the same
	// family the in-cluster controller exports. Outermost (past host
	// normalization) so the counted status is the one the client sees — WAF
	// blocks, rate-limit rejects, and cache hits alike. host is bounded to the
	// Ingress-declared known-host set (EdgeHosts), so a random-Host flood in
	// serve-all mode can't grow series cardinality, while real hosts keep EXACT
	// per-host labels for the observation system.
	m.Use(edge.Requests(edgeHosts.IsKnownHost))
	if !disableLog {
		m.Use(logger.Stdout())
	}
	// Strip any client-supplied WAF-validated claim — unconditionally (even with
	// EDGE_WAF_ENABLED=false) and before the WAF, so a client can never smuggle
	// a claim through this edge to the core and rules never see a spoofed value.
	m.Use(edge.StripWAFClaim())
	if ewaf != nil {
		m.Use(ewaf.Global())
		m.Use(ewaf.Zone())
		// Past both rulesets: stamp the claim the core's WAF_VALIDATED_PROXY
		// requires (only once a CP snapshot has landed — see ClaimStamp).
		m.Use(ewaf.ClaimStamp())
	}
	if ecoraza != nil {
		// Coraza runs right after the CEL WAF — a second signature-based firewall
		// layer, before rate limiting so blocked traffic never burns rate budget.
		// Defense-in-depth: the core re-runs its own Coraza (no claim stamped).
		m.Use(ecoraza.Global())
		m.Use(ecoraza.Zone())
	}
	if erl != nil {
		// Rate limits run after the WAF — WAF-blocked traffic never burns rate
		// budget, mirroring the controller's order — and BEFORE the response
		// cache, so edge-enforced limits apply to cache hits too (the core's
		// per-pod counters still never see edge cache hits).
		m.Use(erl.Global())
		m.Use(erl.Zone())
	}
	if country != nil || asn != nil {
		m.Use(forwardGeoHeaders(country, asn))
	}
	if respCache != nil {
		// CacheEgress sits just outside the cache: it observes X-Cache and
		// counts body bytes for every managed response (HITs, STALEs, MISSes)
		// so billing can account for cache-HIT egress that never reaches the origin.
		m.Use(edge.CacheEgress(edgeHosts.IsKnownHost))
		// CacheStatus sits between CacheEgress and the cache: it stamps
		// X-Cache: BYPASS on responses the cache declined to manage (non-cacheable
		// method, upgrade, Range, or Cacheable=false), so every response under the
		// cache carries an explicit X-Cache status. CacheEgress skips BYPASS bytes.
		m.Use(edge.CacheStatus())
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

// envBytes reads a byte-size env var that may carry a human-readable unit suffix
// (e.g. "2gib", "512mb", "1.5 GiB"). A bare number is bytes, so existing numeric
// values keep working. On a parse error it logs and falls back to def, matching
// envInt64's lenient posture.
func envBytes(key string, def int64) int64 {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	n, err := parseBytes(v)
	if err != nil {
		slog.Warn("edge: invalid byte size; using default", "key", key, "value", v, "default", def, "error", err)
		return def
	}
	return n
}

// parseBytes parses a size like "10", "10b", "2kb", "2kib", "512mb", "1gib",
// "1.5gb". Units are case-insensitive; decimal (kb/mb/gb/tb = 1000ⁿ) and binary
// (kib/mib/gib/tib = 1024ⁿ) suffixes are both accepted, and a missing unit means
// bytes. The result is rounded to the nearest byte and must be ≥ 1.
func parseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	// Split into the leading numeric literal and the trailing unit.
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.' || s[i] == '+' || s[i] == '-') {
		i++
	}
	num, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	mult, ok := byteUnit(strings.ToLower(strings.TrimSpace(s[i:])))
	if !ok {
		return 0, fmt.Errorf("unknown size unit in %q", s)
	}
	v := num * mult
	if v < 1 {
		return 0, fmt.Errorf("size %q must be >= 1 byte", s)
	}
	return int64(v + 0.5), nil
}

// byteUnit maps a (lowercased) size suffix to its byte multiplier. "" / "b" are
// bytes; k/m/g/t are decimal (1000ⁿ), ki/mi/gi/ti (with optional trailing "b")
// are binary (1024ⁿ).
func byteUnit(u string) (float64, bool) {
	switch u {
	case "", "b":
		return 1, true
	case "k", "kb":
		return 1e3, true
	case "ki", "kib":
		return 1 << 10, true
	case "m", "mb":
		return 1e6, true
	case "mi", "mib":
		return 1 << 20, true
	case "g", "gb":
		return 1e9, true
	case "gi", "gib":
		return 1 << 30, true
	case "t", "tb":
		return 1e12, true
	case "ti", "tib":
		return 1 << 40, true
	}
	return 0, false
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
