// Command edge-controlplane is the in-cluster HTTPS REST service that
// distributes per-edge TLS cert+key (and, in Phase 2, WAF rules) to the
// out-of-cluster edge proxy. See ../../../EDGE.md.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/go/edgecp"
	"github.com/moonrhythm/parapet-ingress-controller/go/k8s"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	addr := envOr("CP_LISTEN", ":8443")
	watchNamespace := os.Getenv("WATCH_NAMESPACE") // "" = all namespaces
	podNamespace := os.Getenv("POD_NAMESPACE")     // bounds the global WAF ruleset
	tlsCert := os.Getenv("CP_TLS_CERT")            // server cert (required)
	tlsKey := os.Getenv("CP_TLS_KEY")              // server key (required)
	tokensJSON := os.Getenv("CP_TOKENS")           // {"<token>":["acme.com","*.acme.com"]}
	tokensFile := os.Getenv("CP_TOKENS_FILE")      // alternative: path to that JSON
	wafEnabled := os.Getenv("CP_WAF_ENABLED") == "true"

	if tlsCert == "" || tlsKey == "" {
		slog.Error("CP_TLS_CERT and CP_TLS_KEY are required (the API distributes private keys; HTTPS is mandatory)")
		os.Exit(1)
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
	authz := edgecp.NewAuthz(tokens)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reloader := edgecp.NewReloader(store, watchNamespace)
	go reloader.Start(ctx)

	server := edgecp.NewServer(store, authz)

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
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	slog.Info("edge control plane listening", "addr", addr, "tokens", len(tokens), "waf", wafEnabled)
	if err := srv.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}

// loadTokens reads the token→domains map from inline JSON or a file (file wins
// if both are set, so a mounted Secret can override the env default).
func loadTokens(inline, file string) (map[string][]string, error) {
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
	var m map[string][]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, err
	}
	return m, nil
}
