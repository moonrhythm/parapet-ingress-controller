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
	watchNamespace := os.Getenv("WATCH_NAMESPACE") // "" = all namespaces
	podNamespace := os.Getenv("POD_NAMESPACE")     // bounds the global WAF ruleset
	tlsCert := os.Getenv("CP_TLS_CERT")            // server cert (with CP_TLS_KEY → HTTPS)
	tlsKey := os.Getenv("CP_TLS_KEY")              // server key
	tokensJSON := os.Getenv("CP_TOKENS")           // {"<token>":["acme.com",...]} or {"<token>":{"id","domains","disabled"}}
	tokensFile := os.Getenv("CP_TOKENS_FILE")      // alternative: path to that JSON
	wafEnabled := os.Getenv("CP_WAF_ENABLED") == "true"
	caCertPath := os.Getenv("EDGE_CA_CERT")                 // provided-mode edge CA cert (with EDGE_CA_KEY → enable issuance)
	caKeyPath := os.Getenv("EDGE_CA_KEY")                   // provided-mode edge CA private key
	caSecret := os.Getenv("EDGE_CA_SECRET")                 // managed-mode edge CA Secret in POD_NAMESPACE; "" + no provided files = issuance off
	bootstrapCA := os.Getenv("EDGE_CA_BOOTSTRAP") == "true" // run-once: self-generate the CA into its Secret, then exit
	caTTL := DefaultDuration("EDGE_CA_TTL", edgecp.DefaultCATTL)
	clientCertTTL := DefaultDuration("EDGE_CLIENTCERT_TTL", edgecp.DefaultClientCertTTL)
	clientCertSkew := DefaultDuration("EDGE_CLIENTCERT_SKEW", edgecp.DefaultClientCertSkew)

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

	if err := k8s.Init(); err != nil {
		slog.Error("k8s init", "err", err)
		os.Exit(1)
	}

	store := edgecp.NewCertStore()
	authz := edgecp.NewAuthzEntries(tokens)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reloader := edgecp.NewReloader(store, watchNamespace)
	go reloader.Start(ctx)

	server := edgecp.NewServer(store, authz)

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
		server = server.WithSigner(signer)
		slog.Info("edge control plane: data-plane issuance enabled (provided CA)",
			"ca_id", signer.CAID(), "leaf_ttl", clientCertTTL)

	case caSecret != "":
		if podNamespace == "" {
			slog.Error("managed edge CA (EDGE_CA_SECRET) requires POD_NAMESPACE")
			os.Exit(1)
		}
		// Install the signer from the CA Secret the bootstrap Job populated. If it
		// isn't there yet (CP started before the Job), poll and install when it
		// lands — so the CP self-heals without a restart.
		installSigner := func() bool {
			// Read via the namespace-wide list the CP already has (list/watch), so
			// serving needs no extra `get` grant — only the bootstrap Job (its own
			// scoped SA) writes the CA.
			secs, err := k8s.GetSecrets(ctx, podNamespace)
			if err != nil {
				return false
			}
			var crt, key []byte
			for i := range secs {
				if secs[i].Name == caSecret {
					crt, key = secs[i].Data["tls.crt"], secs[i].Data["tls.key"]
					break
				}
			}
			if len(crt) == 0 || len(key) == 0 {
				return false
			}
			signer, warnings, err := edgecp.NewProvidedSigner(crt, key, clientCertTTL, clientCertSkew)
			if err != nil {
				slog.Error("managed edge CA signer", "err", err)
				return false
			}
			for _, msg := range warnings {
				slog.Warn("edge CA: " + msg)
			}
			server.SetSigner(signer)
			slog.Info("edge control plane: data-plane issuance enabled (managed CA)",
				"ca_id", signer.CAID(), "secret", podNamespace+"/"+caSecret, "leaf_ttl", clientCertTTL)
			return true
		}
		if !installSigner() {
			slog.Warn("edge CA not yet provisioned in " + podNamespace + "/" + caSecret +
				" — run the bootstrap Job; data-plane issuance disabled until it lands")
			go func() {
				t := time.NewTicker(10 * time.Second)
				defer t.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						if installSigner() {
							return
						}
					}
				}
			}()
		}
	}

	// Phase 2/3: optionally distribute the WAF (GET /v1/waf): the global baseline
	// (Phase 2) plus tenant zones + host→zone bindings derived from Ingresses
	// (Phase 3), scoped per edge to its allowed domains.
	if wafEnabled {
		wafStore := edgecp.NewWafStore()
		wafReloader := edgecp.NewWafReloader(wafStore, watchNamespace, podNamespace)
		ingReloader := edgecp.NewIngressReloader(wafStore, watchNamespace)
		// Load synchronously before serving so the first edge fetch sees the full
		// payload (global + zones + host→zone), not a half-populated store.
		if err := wafReloader.LoadOnce(ctx); err != nil {
			slog.Error("edgecp: initial waf load failed", "err", err)
		}
		if err := ingReloader.LoadOnce(ctx); err != nil {
			slog.Error("edgecp: initial ingress load failed", "err", err)
		}
		go wafReloader.Watch(ctx)
		go ingReloader.Watch(ctx)
		server = server.WithWAF(wafStore)
		slog.Info("edge control plane: WAF distribution enabled", "pod_namespace", podNamespace)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if tlsEnabled {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	slog.Info("edge control plane listening", "addr", addr, "tokens", len(tokens), "waf", wafEnabled, "tls", tlsEnabled)

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
