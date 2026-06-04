package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/edgecp/converge"
)

// runConvergeStatus is the run-once converge-status mode (EDGE_CONVERGE_STATUS=true): it
// reads the cross-plane convergence state from Prometheus and exits 0 ONLY when every
// plane has reached the target ca_id, else 1 with the named blockers. It is what sub-PR
// 5's revoke Job calls before the destructive OLD-drop. It performs NO writes.
//
// It NEVER touches the serving issuance path; the Prometheus client is confined here.
func runConvergeStatus() {
	promURL := os.Getenv("EDGE_CONVERGE_PROM_URL")
	if promURL == "" {
		slog.Error("EDGE_CONVERGE_PROM_URL is required for converge-status")
		os.Exit(1)
	}
	cfg := converge.Config{
		ExpectedCP:   envInt("EDGE_CONVERGE_EXPECTED_CP", 0),
		ExpectedCore: envInt("EDGE_CONVERGE_EXPECTED_CORE", 0),
		MinEdges:     envInt("EDGE_CONVERGE_MIN_EDGES", 0),
		Freshness:    DefaultDuration("EDGE_CONVERGE_FRESHNESS", 5*time.Minute),
		Exclude:      parseExcludes(os.Getenv("EDGE_CONVERGE_EXCLUDE")),
		// Active-flip drop-checkpoint pins. When ExpectedActiveSignerFP is set, the predicate
		// runs the full interlock (every CP replica + good edge NEW-signed, blacklist
		// converged via ExpectedAuthzGen, revoked id has zero NEW issuances). The revoke tool
		// supplies these; an operator-driven plain rotation-drop leaves them empty (ca_id-only).
		ExpectedTargetCAID:     os.Getenv("EDGE_CONVERGE_EXPECTED_CA_ID"),
		ExpectedActiveSignerFP: os.Getenv("EDGE_CONVERGE_EXPECTED_SIGNER_FP"),
		ExpectedAuthzGen:       envFloat("EDGE_CONVERGE_EXPECTED_AUTHZ_GEN", 0),
		RevokedEdgeID:          os.Getenv("EDGE_CONVERGE_REVOKED_EDGE_ID"),
	}
	stableReads := envInt("EDGE_CONVERGE_STABLE_READS", 2)
	pollInterval := DefaultDuration("EDGE_CONVERGE_POLL_INTERVAL", 30*time.Second)
	scrapeInterval := DefaultDuration("EDGE_CONVERGE_SCRAPE_INTERVAL", 15*time.Second)
	refreshInterval := DefaultDuration("EDGE_REFRESH_INTERVAL", 300*time.Second)

	// Cadence safety (a refusal, not a default): the reads must SPAN enough time to
	// distinguish a swap-window blip from steady state — at least 2 scrapes AND one
	// refresh interval. Otherwise a flapping gauge could read converged in the gap.
	if stableReads < 2 {
		slog.Error("EDGE_CONVERGE_STABLE_READS must be >= 2 (one read can't distinguish a flap)")
		os.Exit(1)
	}
	if pollInterval <= 0 {
		slog.Error("EDGE_CONVERGE_POLL_INTERVAL must be > 0")
		os.Exit(1)
	}
	if err := checkCadence(cadenceWindow(pollInterval, stableReads), scrapeInterval, refreshInterval); err != nil {
		slog.Error("converge cadence unsafe", "err", err)
		os.Exit(1)
	}

	q, err := converge.NewPromQuerier(promURL)
	if err != nil {
		slog.Error("converge: prometheus client", "err", err)
		os.Exit(1)
	}

	// The revoked-token absence probe (proves the blacklisted token can no longer mint a
	// NEW-CA leaf). Optional inputs; absent ⇒ the probe does not run ⇒ the predicate
	// fail-closes with revoked-unverified (correct for a revoke-driven drop).
	revokedToken := os.Getenv("EDGE_CONVERGE_REVOKED_TOKEN")
	cpURL := os.Getenv("EDGE_CONVERGE_CP_URL")
	// A pinned CA that was requested but can't be read is a HARD error — never silently
	// fall back to system roots for the security probe.
	var cpCA []byte
	if p := os.Getenv("EDGE_CONVERGE_CP_CA"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			slog.Error("converge: cannot read EDGE_CONVERGE_CP_CA (pin requested)", "path", p, "err", err)
			os.Exit(1)
		}
		cpCA = b
	}

	ctx := context.Background()
	var last converge.Result
	for i := 0; i < stableReads; i++ {
		if i > 0 {
			time.Sleep(pollInterval)
		}
		obs, err := converge.Snapshot(ctx, q, cfg.Freshness, time.Now(), cfg.RevokedEdgeID, cfg.ExpectedActiveSignerFP)
		if err != nil {
			slog.Error("converge: prometheus query failed; NOT converged (fail-closed)", "err", err)
			os.Exit(1)
		}
		if revokedToken != "" && cpURL != "" {
			if status, ran := probeRevoked(cpURL, cpCA, revokedToken); ran {
				obs.RevokedProbeRan = true
				obs.RevokedProbeStatus = status
			}
		}
		last = converge.Evaluate(obs, cfg, time.Now())
		if !last.Converged {
			break // a single non-converged read is decisive (fail-closed)
		}
	}

	if !last.Converged {
		slog.Error("NOT converged — OLD CA must NOT be dropped", "target", last.Target, "blockers", blockerStrings(last.Blockers))
		os.Exit(1)
	}
	for _, ex := range last.Excluded {
		slog.Warn("converge: edge excluded from the convergence veto", "edge_id", ex.EdgeID, "reason", ex.Reason)
	}
	slog.Info("CONVERGED — every plane has reached the target ca_id; OLD CA is safe to drop",
		"target", last.Target, "stable_reads", stableReads)
	os.Exit(0)
}

// cadenceWindow is the wall-clock the stable reads SPAN: N reads have N-1 gaps.
func cadenceWindow(poll time.Duration, reads int) time.Duration {
	return poll * time.Duration(reads-1)
}

// checkCadence refuses a window too short to distinguish a swap-window flap from steady
// state: it must cover at least 2 scrapes AND one refresh interval.
func checkCadence(window, scrape, refresh time.Duration) error {
	if window < 2*scrape {
		return fmt.Errorf("read window %s < 2×scrape_interval %s", window, 2*scrape)
	}
	if window < refresh {
		return fmt.Errorf("read window %s < EDGE_REFRESH_INTERVAL %s", window, refresh)
	}
	return nil
}

func blockerStrings(bs []converge.Blocker) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = b.Plane + "/" + b.Reporter + ":" + b.Reason
	}
	return out
}

// parseExcludes parses "id1=reason one,id2=reason two" into reason-required excludes.
func parseExcludes(s string) []converge.ExcludedEdge {
	var out []converge.ExcludedEdge
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, reason, _ := strings.Cut(part, "=")
		out = append(out, converge.ExcludedEdge{EdgeID: strings.TrimSpace(id), Reason: strings.TrimSpace(reason)})
	}
	return out
}

// probeRevoked POSTs to the CP's /v1/edge-cert with the (allegedly revoked) token. A
// disabled token is rejected at auth (401/403) BEFORE the CSR is parsed, so a minimal
// body suffices. ran=false on a transport error (the caller leaves RevokedProbeRan=false
// ⇒ fail-closed). The CP server cert is verified against cpCA when provided.
func probeRevoked(cpURL string, cpCA []byte, token string) (status int, ran bool) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(cpCA) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cpCA) {
			// A pin was requested but the PEM is unusable: fail closed (ran=false ⇒
			// revoked-unverified) rather than verify against system roots.
			slog.Error("converge: EDGE_CONVERGE_CP_CA is not a usable certificate; not probing (fail-closed)")
			return 0, false
		}
		tlsCfg.RootCAs = pool
	}
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(cpURL, "/")+"/v1/edge-cert", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return 0, false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	return resp.StatusCode, true
}
