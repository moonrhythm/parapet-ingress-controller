// Command edge-controlplane is the in-cluster HTTPS REST service that
// distributes per-edge TLS cert+key (and, in Phase 2, WAF rules) to the
// out-of-cluster edge proxy. See ../../EDGE.md.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"

	"github.com/moonrhythm/parapet-ingress-controller/edgecp"
	"github.com/moonrhythm/parapet-ingress-controller/k8s"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// providedGeneration derives the trust-bundle generation for a mounted (provided) CA,
// which has no Secret resourceVersion. It prefers EDGE_CA_PROVIDED_GENERATION (the
// operator bumps it on rotation — strictly-increasing for determinism), else falls back
// to the cert file's mtime as unix seconds (a remount with a newer file advances it).
// It must advance on every provided-CA rotation, or the core rejects the new bundle as a
// rollback (gen <= held). 0 is never returned (cold value 1).
func providedGeneration(caCertPath string) uint64 {
	if v := os.Getenv("EDGE_CA_PROVIDED_GENERATION"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			return n
		}
		slog.Warn("EDGE_CA_PROVIDED_GENERATION must be a positive integer; falling back to cert mtime", "value", v)
	}
	if fi, err := os.Stat(caCertPath); err == nil {
		if mt := fi.ModTime().Unix(); mt > 0 {
			return uint64(mt)
		}
	}
	return 1
}

// envInt reads a base-10 int from env, or returns def (on unset/invalid).
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		slog.Warn("invalid int; using default", "key", key, "value", v, "default", def)
	}
	return def
}

// envFloat reads a float64 env var (the converge authz-generation pin is a float
// fingerprint). An unparseable value falls back to def with a loud warning.
func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
		slog.Warn("invalid float; using default", "key", key, "value", v, "default", def)
	}
	return def
}

// k8sRW adapts the package-level k8s secret read/write funcs to edgecp.SecretRW for
// the CA bootstrap (the only writer of the CA Secret).
type k8sRW struct{}

func (k8sRW) GetSecret(ctx context.Context, ns, name string) (*v1.Secret, error) {
	return k8s.GetSecret(ctx, ns, name)
}

func (k8sRW) UpdateSecret(ctx context.Context, ns string, s *v1.Secret) (*v1.Secret, error) {
	return k8s.UpdateSecret(ctx, ns, s)
}

func main() {
	addr := envOr("CP_LISTEN", ":8443")
	metricsListen := envOr("CP_METRICS_LISTEN", ":9187") // "" disables; SEPARATE unauthenticated listener (non-secret: ca_id fingerprints, counters, generations)
	watchNamespace := os.Getenv("WATCH_NAMESPACE")       // "" = all namespaces
	podNamespace := os.Getenv("POD_NAMESPACE")           // bounds the global WAF ruleset
	tlsCert := os.Getenv("CP_TLS_CERT")                  // server cert (with CP_TLS_KEY → HTTPS)
	tlsKey := os.Getenv("CP_TLS_KEY")                    // server key
	tokensJSON := os.Getenv("CP_TOKENS")                 // {"<token>":["acme.com",...]} or {"<token>":{"id","domains","disabled"}}
	tokensFile := os.Getenv("CP_TOKENS_FILE")            // alternative: path to that JSON
	wafEnabled := os.Getenv("CP_WAF_ENABLED") == "true"
	ratelimitEnabled := os.Getenv("CP_RATELIMIT_ENABLED") == "true"
	cacheEnabled := os.Getenv("CP_CACHE_ENABLED") == "true"
	caCertPath := os.Getenv("EDGE_CA_CERT")                 // provided-mode edge CA cert (with EDGE_CA_KEY → enable issuance)
	caKeyPath := os.Getenv("EDGE_CA_KEY")                   // provided-mode edge CA private key
	caSecret := os.Getenv("EDGE_CA_SECRET")                 // managed-mode edge CA Secret in POD_NAMESPACE; "" + no provided files = issuance off
	bootstrapCA := os.Getenv("EDGE_CA_BOOTSTRAP") == "true" // run-once: self-generate the CA into its Secret, then exit
	rotateCA := os.Getenv("EDGE_CA_ROTATE") == "true"       // run-once: stage a NEW CA alongside OLD (overlap), then exit
	caTTL := DefaultDuration("EDGE_CA_TTL", edgecp.DefaultCATTL)
	clientCertTTL := DefaultDuration("EDGE_CLIENTCERT_TTL", edgecp.DefaultClientCertTTL)
	clientCertSkew := DefaultDuration("EDGE_CLIENTCERT_SKEW", edgecp.DefaultClientCertSkew)

	// Run-once converge-status (a Job/CLI): read the cross-plane convergence state from
	// Prometheus and exit 0 only if every plane reached the target ca_id. Read-only, no
	// k8s, no TLS, no serving — what sub-PR 5's revoke Job calls before the OLD-drop.
	if os.Getenv("EDGE_CONVERGE_STATUS") == "true" {
		runConvergeStatus() // exits
	}

	// Run-once revoke (a Job): sever one edge id by driving the full phased CA rotation
	// (widen → flip → trim), gating every irreversible step on cross-plane convergence.
	// Like the other run-once modes it never serves; the Prometheus client stays confined
	// to this CLI path. See runRevoke for the step/gate sequence and resumability.
	if os.Getenv("EDGE_CA_REVOKE") == "true" {
		runRevoke() // exits
	}

	// Run-once CA bootstrap (a Job): adopt-or-generate the edge CA into its Secret
	// (never regenerate a once-populated CA — the anti-regeneration guard), then
	// exit. Needs neither tokens nor TLS; it never serves.
	if bootstrapCA {
		name := caSecret
		if name == "" {
			name = "parapet-edge-ca"
		}
		if podNamespace == "" {
			slog.Error("EDGE_CA_BOOTSTRAP requires POD_NAMESPACE (the CA Secret's namespace)")
			os.Exit(1)
		}
		if err := k8s.Init(); err != nil {
			slog.Error("k8s init", "err", err)
			os.Exit(1)
		}
		if _, _, err := edgecp.EnsureCA(context.Background(), k8sRW{}, podNamespace, name, caTTL); err != nil {
			slog.Error("bootstrap edge CA", "err", err)
			os.Exit(1)
		}
		slog.Info("edge CA bootstrapped/adopted", "secret", podNamespace+"/"+name)
		os.Exit(0)
	}

	// Run-once CA rotation (a Job): stage a NEW CA alongside OLD (tls.crt =
	// OLD++NEW, NEW key in tls-new.key, phase=overlap, active=old), then exit. This
	// is non-destructive — OLD stays trusted and active; the serving CPs hot-reload
	// the wider bundle and the core trusts it with no change. Like bootstrap it
	// neither serves nor needs tokens/TLS.
	if rotateCA {
		name := caSecret
		if name == "" {
			name = "parapet-edge-ca"
		}
		if podNamespace == "" {
			slog.Error("EDGE_CA_ROTATE requires POD_NAMESPACE (the CA Secret's namespace)")
			os.Exit(1)
		}
		if err := k8s.Init(); err != nil {
			slog.Error("k8s init", "err", err)
			os.Exit(1)
		}
		bundle, err := edgecp.RotateCA(context.Background(), k8sRW{}, podNamespace, name, caTTL)
		if err != nil {
			slog.Error("rotate edge CA", "err", err)
			os.Exit(1)
		}
		slog.Info("edge CA rotated to overlap (OLD++NEW staged; OLD still active)",
			"secret", podNamespace+"/"+name, "bundle_bytes", len(bundle))
		os.Exit(0)
	}

	// TLS is on when both cert+key are set, off when both are empty (plaintext
	// HTTP, for a trusted private network — tunnel / mesh / VPC peering where the
	// transport is already encrypted/authenticated). One-of-two is a config error.
	tlsEnabled := tlsCert != "" || tlsKey != ""
	if tlsEnabled && (tlsCert == "" || tlsKey == "") {
		slog.Error("CP_TLS_CERT and CP_TLS_KEY must be set together (or both empty for plaintext on a private network)")
		os.Exit(1)
	}
	if !tlsEnabled {
		// The API distributes private keys + a bearer token in cleartext, so this
		// is only safe behind a private, encrypted transport. Make that loud.
		slog.Warn("edge control plane: TLS DISABLED — serving plaintext HTTP. " +
			"Only run this on a trusted private network (tunnel/mesh/VPC); the API " +
			"carries private keys and bearer tokens in the clear.")
	}

	tokens, err := loadTokens(tokensJSON, tokensFile)
	if err != nil {
		slog.Error("load edge tokens", "err", err)
		os.Exit(1)
	}
	if len(tokens) == 0 {
		slog.Error("no edge tokens configured (set CP_TOKENS or CP_TOKENS_FILE); refusing to start with an open key-distribution API")
		os.Exit(1)
	}
	// Refuse duplicate data-plane edge ids: two tokens sharing an id would collide on the
	// edge_id label, shadowing one edge's series and silently masking a partitioned edge
	// as converged in the OLD-drop interlock.
	if dupID := duplicateEdgeID(tokens); dupID != "" {
		slog.Error("duplicate edge id across tokens; each data-plane edge id must be unique", "id", dupID)
		os.Exit(1)
	}

	if err := k8s.Init(); err != nil {
		slog.Error("k8s init", "err", err)
		os.Exit(1)
	}

	store := edgecp.NewCertStore()
	authz := edgecp.NewAuthzEntries(tokens)
	// Publish the expected-edge reporter set + the blacklist-barrier fingerprint that the
	// OLD-drop convergence interlock reads (the registry is static today).
	edgecp.SetRegistryMetrics(tokens)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reloader := edgecp.NewReloader(store, watchNamespace, caSecret)
	go reloader.Start(ctx)

	server := edgecp.NewServer(store, authz)

	// Bound concurrent edge-cert signing so a rotation's fleet-wide re-mint surge sheds
	// with 503 + Retry-After instead of saturating the CPU-bound signer. Default to
	// GOMAXPROCS in-flight (signing is fast; this is a safety valve, not a tight cap).
	signConcurrency := envInt("CP_EDGE_SIGN_CONCURRENCY", runtime.GOMAXPROCS(0))
	signRetryAfter := envInt("CP_EDGE_SIGN_RETRY_AFTER", 5)
	server = server.WithSignConcurrency(signConcurrency, signRetryAfter)

	// Bound concurrent blocked long-pollers on the TOKENLESS GET /v1/trust-bundle?watch=1 so
	// a flood can't pin a goroutine each and exhaust memory (defense-in-depth above the
	// edge/core-only NetworkPolicy). Sized generously — one long-poll per core + idle edge —
	// so it never sheds legitimate traffic; over-limit gets 503 + Retry-After. 0 disables.
	server = server.WithWatchConcurrency(envInt("CP_TRUST_WATCH_CONCURRENCY", 1024), envInt("CP_TRUST_WATCH_RETRY_AFTER", 5))

	// Data-plane client-cert issuance (POST /v1/edge-cert) + the tokenless trust
	// bundle (GET /v1/trust-bundle). Two ways to supply the edge CA:
	//   provided — mount EDGE_CA_CERT/EDGE_CA_KEY (operator's PKI).
	//   managed  — EDGE_CA_SECRET: load the CA the bootstrap Job generated+persisted.
	// Neither ⇒ /v1/edge-cert 404s, /v1/trust-bundle 503s (issuance off).
	if (caCertPath != "") != (caKeyPath != "") {
		slog.Error("EDGE_CA_CERT and EDGE_CA_KEY must be set together")
		os.Exit(1)
	}
	switch {
	case caCertPath != "":
		certPEM, err := os.ReadFile(caCertPath)
		if err != nil {
			slog.Error("read EDGE_CA_CERT", "err", err)
			os.Exit(1)
		}
		keyPEM, err := os.ReadFile(caKeyPath)
		if err != nil {
			slog.Error("read EDGE_CA_KEY", "err", err)
			os.Exit(1)
		}
		signer, warnings, err := edgecp.NewProvidedSigner(certPEM, keyPEM, clientCertTTL, clientCertSkew)
		if err != nil {
			slog.Error("build edge CA signer", "err", err)
			os.Exit(1)
		}
		for _, msg := range warnings {
			slog.Warn("edge CA: " + msg)
		}
		server.ExpectIssuance()
		// Provided mode has no Secret resourceVersion to derive the generation from, so
		// take it from EDGE_CA_PROVIDED_GENERATION (operator bumps it on each rotation) or
		// the cert file's mtime. A fixed value would make provided-CA rotation impossible
		// (the core rejects the new bundle at gen <= held). Rotating a mounted CA thus
		// REQUIRES remounting EDGE_CA_CERT/KEY (a newer mtime) or bumping the env, AND
		// restarting this process — there is no fsnotify here. Managed mode (below)
		// hot-reloads via the CA-Secret watch.
		providedGen := providedGeneration(caCertPath)
		server = server.WithSigner(signer, providedGen)
		slog.Info("edge control plane: data-plane issuance enabled (provided CA)",
			"ca_id", signer.CAID(), "generation", providedGen, "leaf_ttl", clientCertTTL)

	case caSecret != "":
		if podNamespace == "" {
			slog.Error("managed edge CA (EDGE_CA_SECRET) requires POD_NAMESPACE")
			os.Exit(1)
		}
		// Hot-reload the signer from the CA Secret the bootstrap/rotation Job writes.
		// The reloader reads via the namespace-wide list the CP already watches (no
		// extra `get` grant) and SetSigner's on every ca_id change — so a rotation's
		// OLD++NEW write (or a not-yet-provisioned CA landing later) propagates with
		// no restart.
		server.ExpectIssuance()
		// Rotation-stuck alert threshold: page (edge_ca_rotation_stuck=1) once the CA Secret
		// has sat in the OLD++NEW overlap this long — a half-applied rotation means a
		// rotated-out edge is still trusted. Size it above a full revoke's expected duration
		// (both convergence gates); default 24h. The reloader feeds the live overlap state.
		edgecp.SetRotationStuckDeadline(time.Duration(envInt("EDGE_CA_ROTATION_DEADLINE", 86400)) * time.Second)
		signerReloader := edgecp.NewSignerReloader(server, podNamespace, caSecret, clientCertTTL, clientCertSkew)
		if err := signerReloader.LoadOnce(ctx); err != nil {
			slog.Error("edgecp: initial edge CA signer load failed", "err", err)
		}
		if server.SignerLoaded() {
			slog.Info("edge control plane: data-plane issuance enabled (managed CA)",
				"ca_id", server.CurrentCAID(), "secret", podNamespace+"/"+caSecret, "leaf_ttl", clientCertTTL)
		} else {
			slog.Warn("edge CA not yet provisioned in " + podNamespace + "/" + caSecret +
				" — run the bootstrap Job; data-plane issuance disabled until it lands")
		}
		go signerReloader.Watch(ctx)
	}

	// Phase 2/3: optionally distribute the WAF (GET /v1/waf): the global baseline
	// (Phase 2) plus tenant zones + host→zone bindings derived from Ingresses
	// (Phase 3), scoped per edge to its allowed domains. Rate-limit distribution
	// (GET /v1/ratelimit) follows the same model under its own label/annotation;
	// both features share ONE Ingress watch — the reloader feeds whichever
	// stores exist. Stores load synchronously before serving so the first edge
	// fetch sees the full payload, not a half-populated store.
	var wafStore *edgecp.WafStore
	var rlStore *edgecp.RateLimitStore
	var cacheStore *edgecp.CacheStore
	var hostsStore *edgecp.HostsStore
	if wafEnabled {
		wafStore = edgecp.NewWafStore()
		wafReloader := edgecp.NewWafReloader(wafStore, watchNamespace, podNamespace)
		if err := wafReloader.LoadOnce(ctx); err != nil {
			slog.Error("edgecp: initial waf load failed", "err", err)
		}
		go wafReloader.Watch(ctx)
		server = server.WithWAF(wafStore)
		slog.Info("edge control plane: WAF distribution enabled", "pod_namespace", podNamespace)
	}
	if ratelimitEnabled {
		rlStore = edgecp.NewRateLimitStore()
		rlReloader := edgecp.NewRateLimitReloader(rlStore, watchNamespace, podNamespace)
		if err := rlReloader.LoadOnce(ctx); err != nil {
			slog.Error("edgecp: initial ratelimit load failed", "err", err)
		}
		go rlReloader.Watch(ctx)
		server = server.WithRateLimit(rlStore)
		slog.Info("edge control plane: ratelimit distribution enabled", "pod_namespace", podNamespace)
	}
	// Cache-override distribution (GET /v1/cache): the same global+zone model
	// under its own label/annotation, sharing the one Ingress watch (cross-namespace
	// zone binding allowed — overrides are stateless config).
	if cacheEnabled {
		cacheStore = edgecp.NewCacheStore()
		cacheReloader := edgecp.NewCacheReloader(cacheStore, watchNamespace, podNamespace)
		if err := cacheReloader.LoadOnce(ctx); err != nil {
			slog.Error("edgecp: initial cache load failed", "err", err)
		}
		go cacheReloader.Watch(ctx)
		server = server.WithCache(cacheStore)
		slog.Info("edge control plane: cache-override distribution enabled", "pod_namespace", podNamespace)
	}
	// Standalone known-host distribution (GET /v1/hosts) — the edge request
	// metric's host oracle. On by default and independent of WAF/ratelimit, since
	// the metric is always on; it only rides the same Ingress watch.
	if envOr("CP_HOSTS_ENABLED", "true") == "true" {
		hostsStore = edgecp.NewHostsStore()
		server = server.WithHosts(hostsStore)
		slog.Info("edge control plane: hosts distribution enabled")
	}
	if wafStore != nil || rlStore != nil || cacheStore != nil || hostsStore != nil {
		ingReloader := edgecp.NewIngressReloader(wafStore, watchNamespace).WithRateLimit(rlStore).WithCache(cacheStore).WithHosts(hostsStore)
		if err := ingReloader.LoadOnce(ctx); err != nil {
			slog.Error("edgecp: initial ingress load failed", "err", err)
		}
		go ingReloader.Watch(ctx)
	}

	// Optional cache-purge distribution (GET/POST /v1/purges). The read side rides
	// the per-edge bearer token (scoped to the edge's hosts); issuing a purge needs
	// CP_PURGE_ADMIN_TOKEN — a stronger credential than the edges hold. Without that
	// token, issuance is locked out, so refuse to enable an issue-less purge plane.
	var purgeStore *edgecp.PurgeStore
	if os.Getenv("CP_PURGE_ENABLED") == "true" {
		adminToken := os.Getenv("CP_PURGE_ADMIN_TOKEN")
		if adminToken == "" {
			slog.Error("CP_PURGE_ENABLED=true requires CP_PURGE_ADMIN_TOKEN (the credential that gates POST /v1/purges)")
			os.Exit(1)
		}
		purgeStore = edgecp.NewPurgeStore(envInt("CP_PURGE_MAX_ENTRIES", 0))
		server = server.WithPurge(purgeStore, adminToken)
		slog.Info("edge control plane: cache-purge distribution enabled")
	}

	// Change-notification stream (GET /v1/events): a per-edge SSE wake-up signal
	// so the fleet converges in ~seconds instead of one poll interval. The hub
	// samples the stores' version vector and broadcasts on change; edges
	// re-fetch through the scoped, ETag-revalidated endpoints, so authz and
	// fail-static semantics are untouched. Keep the ping cadence under any
	// fronting LB's idle timeout (Google ALB drops idle streams at ~60s), and
	// size the LB's backend/response timeout well above it — the stream is cut
	// at that timeout and the edge transparently reconnects.
	if envOr("CP_EVENTS_ENABLED", "true") == "true" {
		hub := edgecp.NewEventsHub(func() edgecp.EventsSnapshot {
			var snap edgecp.EventsSnapshot
			snap.Certs = store.Version()
			if wafStore != nil {
				snap.WAF = wafStore.Version()
			}
			if rlStore != nil {
				snap.RateLimit = rlStore.Version()
			}
			if cacheStore != nil {
				snap.Cache = cacheStore.Version()
			}
			if hostsStore != nil {
				snap.Hosts = hostsStore.Version()
			}
			if purgeStore != nil {
				snap.Purges = purgeStore.LastSeq()
			}
			return snap
		})
		hub.PingInterval = time.Duration(envInt("CP_EVENTS_PING_INTERVAL", 20)) * time.Second
		hub.MaxSubscribers = envInt("CP_EVENTS_MAX_SUBSCRIBERS", 1024)
		// Per-token cap: replicas share one token (one stream each), so size it
		// >= replicas-per-token. It exists so one edge in a stream-leaking
		// reconnect loop can't eat the global cap and starve the rest of the fleet.
		hub.MaxPerToken = envInt("CP_EVENTS_MAX_PER_TOKEN", 32)
		hub.RetryAfterSecs = envInt("CP_EVENTS_RETRY_AFTER", 30)
		go hub.Run(ctx)
		server = server.WithEvents(hub)
		slog.Info("edge control plane: change-event stream enabled",
			"ping_interval", hub.PingInterval, "max_subscribers", hub.MaxSubscribers)
	}

	// Convergence /metrics on a SEPARATE, unauthenticated listener (never the
	// token-gated API mux, so a scraper reaches it without the bearer token). Only the
	// serving process reaches here — the run-once bootstrap/rotate Jobs os.Exit above.
	// The payload is non-secret (ca_id fingerprints, counters, generations — no key
	// material); a NetworkPolicy must still restrict it to the scraper.
	//
	// The same listener also serves the PUSHED edge-fleet metrics: edges POST their
	// registry snapshots to /v1/metrics on the API (token-gated), and MetricsHandler
	// merges those per-instance snapshots into the CP's own families — one scrape
	// target for the CP + the out-of-cluster fleet. Snapshots expire CP_EDGE_METRICS_TTL
	// seconds after their last push, so a dead edge's series disappear instead of
	// being served stale forever.
	//
	// A failed bind is logged loudly but NOT fatal: the control plane's job is issuance
	// + trust distribution, which must never be taken down because an observability port
	// is contended. A missing /metrics is already loud to the scraper (the target's
	// `up == 0`), and the convergence interlock fails closed on a non-reporting target.
	if metricsListen != "" {
		metricsStore := edgecp.NewMetricsStore(time.Duration(envInt("CP_EDGE_METRICS_TTL", 300)) * time.Second)
		server = server.WithMetricsIngest(metricsStore)
		metricsSrv := &http.Server{
			Addr:              metricsListen,
			Handler:           edgecp.MetricsHandler(metricsStore),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("edge control plane: metrics listener failed; serving API without /metrics", "addr", metricsListen, "err", err)
			}
		}()
		slog.Info("edge control plane: metrics listening", "addr", metricsListen)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// Bound request-header memory per connection on the tokenless API (defense-in-depth
		// against a header flood); 64 KiB is ample for the bearer token + ETag headers.
		MaxHeaderBytes: 64 << 10,
	}
	if tlsEnabled {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	slog.Info("edge control plane listening", "addr", addr, "tokens", len(tokens), "waf", wafEnabled, "ratelimit", ratelimitEnabled, "cache", cacheEnabled, "tls", tlsEnabled)

	if tlsEnabled {
		err = srv.ListenAndServeTLS(tlsCert, tlsKey)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}

// duplicateEdgeID returns the first non-empty edge id shared by two tokens, or "" if all
// data-plane ids are unique. Unique ids are required for the edge_id convergence join.
func duplicateEdgeID(tokens map[string]edgecp.Entry) string {
	seen := make(map[string]struct{}, len(tokens))
	for _, e := range tokens {
		if e.ID == "" {
			continue
		}
		if _, dup := seen[e.ID]; dup {
			return e.ID
		}
		seen[e.ID] = struct{}{}
	}
	return ""
}

// loadTokens reads the registry from inline JSON or a file (file wins if both are
// set, so a mounted Secret can override the env default). Each value is either the
// legacy domain array (["acme.com",...]) or the richer object
// ({"id":...,"domains":[...],"disabled":true}); both parse into an edgecp.Entry.
func loadTokens(inline, file string) (map[string]edgecp.Entry, error) {
	raw := inline
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		raw = string(b)
	}
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var rawEntries map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &rawEntries); err != nil {
		return nil, err
	}
	entries := make(map[string]edgecp.Entry, len(rawEntries))
	for tok, rm := range rawEntries {
		// Try the legacy array form first, then the richer object form.
		var domains []string
		if err := json.Unmarshal(rm, &domains); err == nil {
			entries[tok] = edgecp.Entry{Domains: domains}
			continue
		}
		var obj struct {
			ID       string   `json:"id"`
			Domains  []string `json:"domains"`
			Disabled bool     `json:"disabled"`
		}
		if err := json.Unmarshal(rm, &obj); err != nil {
			return nil, fmt.Errorf("token %q: %w", tok, err)
		}
		entries[tok] = edgecp.Entry{ID: obj.ID, Domains: obj.Domains, Disabled: obj.Disabled}
	}
	return entries, nil
}

// DefaultDuration reads a Go duration (e.g. "168h") from env, or returns def.
func DefaultDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		slog.Warn("invalid duration; using default", "key", key, "value", v, "default", def)
	}
	return def
}
