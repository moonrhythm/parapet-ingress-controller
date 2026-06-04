package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/caid"
	"github.com/moonrhythm/parapet-ingress-controller/edgecp"
	"github.com/moonrhythm/parapet-ingress-controller/edgecp/converge"
	"github.com/moonrhythm/parapet-ingress-controller/k8s"
)

// runRevoke is the run-once revoke orchestrator (EDGE_CA_REVOKE=true). It severs a single
// edge id by driving the full phased CA rotation, gating every irreversible step on
// cross-plane convergence (never on a timer). It assumes the operator has ALREADY
// blacklisted the edge's token (disabled:true in CP_TOKENS) and restarted the serving CPs
// — runRevoke verifies that, then:
//
//  1. RotateCA       — widen the bundle to OLD++NEW (non-destructive; OLD still active).
//  2. wait (Gate A)  — every CP + core + edge holds the OLD++NEW bundle (ca_id converged).
//  3. SetActiveNew   — flip the active signer to NEW (new leaves now chain to NEW).
//  4. wait (Gate B)  — every CP replica + good edge is NEW-SIGNED, the blacklist converged
//     on every replica (authz gen), the revoked id has zero NEW issuances,
//     and the live probe rejects the revoked token.
//  5. TrimCA         — DESTRUCTIVE: drop OLD. The core now trusts only NEW, severing every
//     OLD-signed leaf — the revoked edge's, and any straggler.
//
// Every underlying step is idempotent + CAS-looped, so a crash/retry re-enters safely
// (RotateCA/SetActiveNew/TrimCA no-op when already in their target state, and the gates
// re-poll). It NEVER serves and confines the Prometheus client to this CLI path.
func runRevoke() {
	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		slog.Error("EDGE_CA_REVOKE requires POD_NAMESPACE (the CA Secret's namespace)")
		os.Exit(1)
	}
	name := envOr("EDGE_CA_SECRET", "parapet-edge-ca")
	revokedID := strings.ToLower(strings.TrimSpace(os.Getenv("EDGE_CA_REVOKE_EDGE_ID")))
	if revokedID == "" {
		slog.Error("EDGE_CA_REVOKE requires EDGE_CA_REVOKE_EDGE_ID (the edge id to sever)")
		os.Exit(1)
	}
	promURL := os.Getenv("EDGE_CONVERGE_PROM_URL")
	if promURL == "" {
		slog.Error("EDGE_CA_REVOKE requires EDGE_CONVERGE_PROM_URL (the OLD-drop is convergence-gated)")
		os.Exit(1)
	}
	caTTL := DefaultDuration("EDGE_CA_TTL", edgecp.DefaultCATTL)

	// The base convergence expectations (counts + freshness + excludes), shared by both gates.
	base := converge.Config{
		ExpectedCP:   envInt("EDGE_CONVERGE_EXPECTED_CP", 0),
		ExpectedCore: envInt("EDGE_CONVERGE_EXPECTED_CORE", 0),
		MinEdges:     envInt("EDGE_CONVERGE_MIN_EDGES", 0),
		Freshness:    DefaultDuration("EDGE_CONVERGE_FRESHNESS", 5*time.Minute),
		Exclude:      parseExcludes(os.Getenv("EDGE_CONVERGE_EXCLUDE")),
	}

	// The live revoked-token probe is MANDATORY for a revoke (the predicate fail-closes
	// without it). It proves the blacklisted token is actively rejected, not merely absent
	// from the expected set.
	probe := revokedProbe{
		token: os.Getenv("EDGE_CONVERGE_REVOKED_TOKEN"),
		cpURL: os.Getenv("EDGE_CONVERGE_CP_URL"),
	}
	if probe.token == "" || probe.cpURL == "" {
		slog.Error("EDGE_CA_REVOKE requires EDGE_CONVERGE_REVOKED_TOKEN + EDGE_CONVERGE_CP_URL (the live revoked-token probe is mandatory)")
		os.Exit(1)
	}
	if p := os.Getenv("EDGE_CONVERGE_CP_CA"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			slog.Error("EDGE_CA_REVOKE: cannot read EDGE_CONVERGE_CP_CA (pin requested)", "path", p, "err", err)
			os.Exit(1)
		}
		probe.cpCA = b
	}

	stableReads := envInt("EDGE_CONVERGE_STABLE_READS", 2)
	pollInterval := DefaultDuration("EDGE_CONVERGE_POLL_INTERVAL", 30*time.Second)
	scrapeInterval := DefaultDuration("EDGE_CONVERGE_SCRAPE_INTERVAL", 15*time.Second)
	refreshInterval := DefaultDuration("EDGE_REFRESH_INTERVAL", 300*time.Second)
	deadline := DefaultDuration("EDGE_CA_REVOKE_TIMEOUT", 30*time.Minute)
	if stableReads < 2 {
		slog.Error("EDGE_CONVERGE_STABLE_READS must be >= 2 (one read can't distinguish a flap)")
		os.Exit(1)
	}
	if err := checkCadence(cadenceWindow(pollInterval, stableReads), scrapeInterval, refreshInterval); err != nil {
		slog.Error("EDGE_CA_REVOKE converge cadence unsafe", "err", err)
		os.Exit(1)
	}

	// Preflight: the blacklist MUST already be applied (disabled:true) and converged on
	// every CP. We derive the post-blacklist authz-generation pin from the SAME registry the
	// CPs loaded — Gate B asserts every replica reports it, proving the revoke is everywhere.
	tokens, err := loadTokens(os.Getenv("CP_TOKENS"), os.Getenv("CP_TOKENS_FILE"))
	if err != nil {
		slog.Error("EDGE_CA_REVOKE: load edge tokens", "err", err)
		os.Exit(1)
	}
	if !idDisabled(tokens, revokedID) {
		slog.Error("EDGE_CA_REVOKE: the edge id is not present-and-disabled in CP_TOKENS — blacklist it (disabled:true) and restart all CP first, then re-run",
			"edge_id", revokedID)
		os.Exit(1)
	}
	expectedAuthzGen := edgecp.AuthzGeneration(tokens)

	q, err := converge.NewPromQuerier(promURL)
	if err != nil {
		slog.Error("EDGE_CA_REVOKE: prometheus client", "err", err)
		os.Exit(1)
	}
	if err := k8s.Init(); err != nil {
		slog.Error("k8s init", "err", err)
		os.Exit(1)
	}
	ctx := context.Background()
	rw := k8sRW{}

	// Step 1 — widen (idempotent). The NEW cert is the bundle's last block; its fp + the
	// bundle ca_id pin every downstream step + gate to THIS rotation.
	bundle, err := edgecp.RotateCA(ctx, rw, ns, name, caTTL)
	if err != nil {
		slog.Error("EDGE_CA_REVOKE: rotate (widen) failed", "err", err)
		os.Exit(1)
	}
	newFP, err := lastCertFP(bundle)
	if err != nil {
		slog.Error("EDGE_CA_REVOKE: derive NEW cert fingerprint", "err", err)
		os.Exit(1)
	}
	targetCAID, err := caid.FromPEM(bundle)
	if err != nil {
		slog.Error("EDGE_CA_REVOKE: derive target ca_id", "err", err)
		os.Exit(1)
	}
	slog.Info("EDGE_CA_REVOKE: widened to OLD++NEW; waiting for the trust bundle to converge",
		"edge_id", revokedID, "target_ca_id", targetCAID, "new_fp", newFP)

	// Gate A — the ca_id widen barrier (no fp pin): every core trusts NEW before we flip.
	cfgA := base
	cfgA.ExpectedTargetCAID = targetCAID
	cfgA.RevokedEdgeID = revokedID // benign pre-flip (issuance gate is fp-gated, off here)
	if err := pollUntilConverged(ctx, "widen", q, cfgA, probe, stableReads, pollInterval, deadline); err != nil {
		slog.Error("EDGE_CA_REVOKE: widen did not converge — NOT flipping (nothing destructive done; re-run to resume)", "err", err)
		os.Exit(1)
	}

	// Step 2 — flip the active signer to NEW (reversible until the trim).
	if _, err := edgecp.SetActiveNew(ctx, rw, ns, name, newFP); err != nil {
		slog.Error("EDGE_CA_REVOKE: active flip failed", "err", err)
		os.Exit(1)
	}
	slog.Info("EDGE_CA_REVOKE: flipped active signer to NEW; waiting for every leaf to chain to NEW")

	// Gate B — the destructive-drop interlock: everyone NEW-signed, blacklist converged,
	// the revoked id has zero NEW issuances, and the live probe rejects the revoked token.
	cfgB := base
	cfgB.ExpectedTargetCAID = targetCAID
	cfgB.ExpectedActiveSignerFP = newFP
	cfgB.ExpectedAuthzGen = expectedAuthzGen
	cfgB.RevokedEdgeID = revokedID
	if err := pollUntilConverged(ctx, "drop", q, cfgB, probe, stableReads, pollInterval, deadline); err != nil {
		slog.Error("EDGE_CA_REVOKE: drop checkpoint did not converge — NOT dropping OLD (OLD still trusted; re-run to resume)", "err", err)
		os.Exit(1)
	}

	// Step 3 — DESTRUCTIVE: drop OLD. The core now trusts only NEW; every OLD-signed leaf
	// (the revoked edge's, and any straggler) loses trust.
	if _, err := edgecp.TrimCA(ctx, rw, ns, name, newFP); err != nil {
		slog.Error("EDGE_CA_REVOKE: trim (OLD-drop) failed", "err", err)
		os.Exit(1)
	}
	slog.Info("EDGE_CA_REVOKE complete: OLD dropped, fleet on NEW, revoked edge severed",
		"edge_id", revokedID, "new_ca_id", func() string { id, _ := caid.FromPEM(bundle); return id }())
	os.Exit(0)
}

// revokedProbe carries the inputs for the live revoked-token absence probe, stamped onto
// each Observations before evaluation.
type revokedProbe struct {
	token string
	cpURL string
	cpCA  []byte
}

func (p revokedProbe) stamp(obs *converge.Observations) {
	if status, ran := probeRevoked(p.cpURL, p.cpCA, p.token); ran {
		obs.RevokedProbeRan = true
		obs.RevokedProbeStatus = status
	}
}

// readStable runs one stable-read sequence: stableReads consecutive Prometheus reads, each
// with the live probe, stopping early on the first non-converged read (a single
// non-converged read is decisive — fail-closed). Returns the last Result.
func readStable(ctx context.Context, q converge.Querier, cfg converge.Config, probe revokedProbe, stableReads int, pollInterval time.Duration) converge.Result {
	var last converge.Result
	for i := 0; i < stableReads; i++ {
		if i > 0 {
			time.Sleep(pollInterval)
		}
		obs, err := converge.Snapshot(ctx, q, cfg.Freshness, time.Now(), cfg.RevokedEdgeID, cfg.ExpectedActiveSignerFP)
		if err != nil {
			// A Prometheus blip is transient: treat as non-converged so the outer poll loop
			// retries, never as converged (fail-closed).
			return converge.Result{Blockers: []converge.Blocker{{Plane: "config", Reason: "prometheus-query-failed"}}}
		}
		probe.stamp(&obs)
		last = converge.Evaluate(obs, cfg, time.Now())
		if !last.Converged {
			break
		}
	}
	return last
}

// pollUntilConverged repeats readStable until it converges or the deadline elapses. It is
// the convergence WAIT (steps take minutes as edges re-mint): non-converged is not a
// failure, it's "keep waiting". Only the deadline is a failure — and a timeout leaves the
// rotation at its last completed step (re-run resumes). It logs the live blockers each pass
// so a stall is diagnosable.
func pollUntilConverged(ctx context.Context, label string, q converge.Querier, cfg converge.Config, probe revokedProbe, stableReads int, pollInterval, deadline time.Duration) error {
	start := time.Now()
	for {
		r := readStable(ctx, q, cfg, probe, stableReads, pollInterval)
		if r.Converged {
			for _, ex := range r.Excluded {
				slog.Warn("EDGE_CA_REVOKE: edge excluded from the convergence veto", "gate", label, "edge_id", ex.EdgeID, "reason", ex.Reason)
			}
			slog.Info("EDGE_CA_REVOKE: gate converged", "gate", label, "target", r.Target, "waited", time.Since(start).Round(time.Second))
			return nil
		}
		if time.Since(start) >= deadline {
			return fmt.Errorf("%s gate not converged within %s; blockers=%v", label, deadline, blockerStrings(r.Blockers))
		}
		slog.Info("EDGE_CA_REVOKE: not yet converged; waiting", "gate", label,
			"waited", time.Since(start).Round(time.Second), "blockers", blockerStrings(r.Blockers))
		time.Sleep(pollInterval)
	}
}

// idDisabled reports whether the registry holds an entry for edgeID that is disabled (the
// canonical blacklist state). An absent id returns false (a typo'd id must not pass
// preflight as "already revoked").
func idDisabled(tokens map[string]edgecp.Entry, edgeID string) bool {
	for _, e := range tokens {
		if strings.ToLower(strings.TrimSpace(e.ID)) == edgeID {
			return e.Disabled
		}
	}
	return false
}

// lastCertFP returns the SHA-256 (hex) of the LAST CERTIFICATE block in a bundle — the NEW
// CA during an OLD++NEW overlap (RotateCA appends NEW last). It matches the fp the serving
// signer + the edge derive, so it is the pin every downstream step asserts.
func lastCertFP(bundlePEM []byte) (string, error) {
	var lastDER []byte
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			lastDER = block.Bytes
		}
	}
	if lastDER == nil {
		return "", fmt.Errorf("bundle has no CERTIFICATE block")
	}
	sum := sha256.Sum256(lastDER)
	return hex.EncodeToString(sum[:]), nil
}
