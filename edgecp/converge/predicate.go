// Package converge evaluates whether an edge-CA rotation has CONVERGED across every
// plane — every serving control-plane replica, every core, and every good edge has
// reached the target ca_id — so the destructive OLD-drop (sub-PR 5) can proceed. It is
// the metric-gated, never-timer-gated interlock from EDGE-AUTOTRUST.md.
//
// Evaluate is a PURE function over a metric snapshot (Observations), with zero I/O, so
// the safety predicate is exhaustively unit-testable without a live Prometheus. The
// Prometheus querying that builds Observations lives in source.go. The whole package is
// imported ONLY by the run-once converge-status CLI branch — NEVER by the serving issuance
// path (asserted by import_boundary_test.go), so a Prometheus outage can't break issuance.
//
// FAIL-CLOSED is the contract: the only unsafe move is dropping OLD too early, so a
// missing / partitioned / stale / unverified reporter ALWAYS blocks. Convergence is
// observed==expected COUNTS (never a vacuous all-equal that is also true when nobody
// reports).
package converge

import "time"

// Blocker names one reason convergence is not met: which plane, which reporter, why.
type Blocker struct {
	Plane    string // cp | core | edge | revoked | config
	Reporter string // instance / edge_id / "" for plane-wide
	Reason   string // see the reason constants below
}

// Blocker reason constants (stable strings, surfaced in the verdict).
const (
	ReasonCPTargetSplit       = "cp-target-split"        // CP replicas disagree on the target ca_id
	ReasonGenerationSplit     = "generation-split"       // same ca_id but divergent generation across CP replicas
	ReasonExpectedSetEmpty    = "expected-set-empty"     // zero series across the whole expected set (misconfig)
	ReasonNoTarget            = "no-target"              // no CP advertises a target ca_id
	ReasonCountMismatch       = "count-mismatch"         // observed reporters != expected count
	ReasonUpDown              = "up-down"                // reporter scraped but up==0
	ReasonNeverScraped        = "never-scraped"          // expected reporter has no series at all (vs booting)
	ReasonWrongCAID           = "wrong-ca_id"            // reporter holds a ca_id != target (not converged)
	ReasonNotOverlap          = "not-overlap"            // CP bundle_certs != 2 (OLD++NEW must still be present pre-drop)
	ReasonTargetNotObserved   = "target-not-observed"    // edge hasn't observed the CP target yet
	ReasonRefreshStale        = "refresh-stale"          // edge poll loop hasn't run in the window (frozen-but-scrapable)
	ReasonRemintChurn         = "remint-churn"           // edge has FAILED re-mints in the window
	ReasonLiveOldLeaf         = "live-old-leaf"          // an edge is live on a non-target leaf (even if registry-disabled)
	ReasonAuthzSplit          = "authz-split"            // CP replicas disagree on the authz generation (blacklist not converged)
	ReasonEdgeCountBelowFloor = "edge-count-below-floor" // fewer expected edges than the operator floor (registry/scrape drift)
	ReasonRevokedUnverified   = "revoked-unverified"     // the revoked-token absence probe did not run (fail-closed)
	ReasonRevokedLeafPresent  = "revoked-leaf-present"   // the revoked token can still mint (probe got 2xx)
)

// Config is the operator/Job input. The target ca_id is NOT configured — it is derived
// from the self-describing CP target series (cp-target-split if replicas disagree).
type Config struct {
	ExpectedCP   int // serving CP replicas expected to report
	ExpectedCore int // cores expected to report
	MinEdges     int // FLOOR on the discovered expected-edge set — a registry/scrape
	// drift that empties ExpectedEdges must fail closed, not converge
	// vacuously (the edge loop running zero times). Operator-supplied,
	// a `<` floor (the fleet is registry-scaled, so `!=` would over-block).
	Freshness time.Duration // window within which a reporter must have refreshed
	Exclude   []ExcludedEdge
}

// ExcludedEdge is a LOUD, reason-required convergence-veto waiver for a decommissioned
// edge (never a default; recorded in Result). An empty Reason makes Evaluate refuse.
type ExcludedEdge struct {
	EdgeID string
	Reason string
}

// CPReplica is one serving control-plane replica's scraped state.
type CPReplica struct {
	Instance    string
	Up          bool
	TargetCAID  string  // edge_ca_target_ca_id label
	SignerCAID  string  // edge_ca_signer_fingerprint label
	SignerGen   uint64  // edge_ca_signer_generation value
	BundleCerts int     // edge_ca_bundle_certs value (2 during OLD++NEW overlap)
	AuthzGen    float64 // edge_authz_generation value
}

// CoreReplica is one core's scraped state.
type CoreReplica struct {
	Instance string
	Up       bool
	HeldCAID string // ca_id from trust_bundle_generation
}

// EdgeReporter is one edge's scraped state, keyed by its stable edge_id.
type EdgeReporter struct {
	EdgeID            string
	Up                bool
	LiveCAID          string // edge_clientcert_ca_id label
	ObservedTarget    string // edge_cp_target_ca_id label
	RefreshedInWindow bool   // increase(edge_refresh_total[Freshness]) >= 1
	FailedRemints     bool   // increase(edge_clientcert_remint_total{result!="ok"}[Freshness]) > 0
}

// Observations is the cross-plane metric snapshot Evaluate scores. source.go builds it
// from Prometheus; tests build it directly.
type Observations struct {
	CP            []CPReplica
	Core          []CoreReplica
	Edges         []EdgeReporter // every edge observed LIVE in the window (expected or not)
	ExpectedEdges []string       // edge_ids from edge_registry_total==1 (expected-to-converge set)

	RevokedProbeRan    bool // the revoked-token absence probe was executed
	RevokedProbeStatus int  // its HTTP status (401/403 ⇒ revoked; 2xx ⇒ still mints)
}

// Result is the verdict. Converged is true ONLY when Blockers is empty.
type Result struct {
	Converged bool
	Target    string // the resolved target ca_id ("" if unresolved)
	Blockers  []Blocker
	Excluded  []ExcludedEdge // the waivers applied (echoed for the audit trail)
}

// Evaluate scores convergence against the target ca_id derived from the CP target series.
// Pure: no I/O, no clock beyond `now`. Returns Converged=false with named Blockers for
// every reason the drop is unsafe.
func Evaluate(obs Observations, cfg Config, now time.Time) Result {
	r := Result{Excluded: cfg.Exclude}

	// A reason-required exclude is non-negotiable: an empty Reason is a silent waiver.
	for _, ex := range cfg.Exclude {
		if ex.Reason == "" {
			r.Blockers = append(r.Blockers, Blocker{Plane: "config", Reporter: ex.EdgeID, Reason: "exclude-without-reason"})
		}
	}
	excluded := map[string]bool{}
	for _, ex := range cfg.Exclude {
		excluded[ex.EdgeID] = true
	}

	// Misconfig guard: a sane gate needs positive expectations (incl. an edge floor) so
	// the drop can never be gated on a vacuously-empty plane. MinEdges<=0 is itself a
	// misconfig — the floor must not be silently disabled.
	if cfg.ExpectedCP <= 0 || cfg.ExpectedCore <= 0 || cfg.MinEdges <= 0 {
		r.Blockers = append(r.Blockers, Blocker{Plane: "config", Reason: "expected-counts-unset"})
	}
	if len(obs.CP) == 0 && len(obs.Core) == 0 && len(obs.Edges) == 0 && len(obs.ExpectedEdges) == 0 {
		r.Blockers = append(r.Blockers, Blocker{Plane: "config", Reason: ReasonExpectedSetEmpty})
		return finalize(r) // nothing to score against; fail closed
	}

	// (1) Resolve the target T from the self-describing CP target series. Disagreement is
	// a hard block — never silently pick one and compute downstream against it.
	targets := map[string]int{}
	for _, cp := range obs.CP {
		if cp.Up && cp.TargetCAID != "" {
			targets[cp.TargetCAID]++
		}
	}
	switch len(targets) {
	case 0:
		r.Blockers = append(r.Blockers, Blocker{Plane: "cp", Reason: ReasonNoTarget})
		return finalize(r)
	case 1:
		for t := range targets {
			r.Target = t
		}
	default:
		r.Blockers = append(r.Blockers, Blocker{Plane: "cp", Reason: ReasonCPTargetSplit})
		return finalize(r)
	}
	T := r.Target

	// (2) CP plane: every replica up, signing under T, still serving OLD++NEW (2 certs),
	// with ONE generation for T (the generation-split tripwire) and agreement on authz.
	cpAtT, gens, authz := 0, map[uint64]bool{}, map[float64]bool{}
	for _, cp := range obs.CP {
		if !cp.Up {
			r.Blockers = append(r.Blockers, Blocker{Plane: "cp", Reporter: cp.Instance, Reason: ReasonUpDown})
			continue
		}
		if cp.SignerCAID != T {
			r.Blockers = append(r.Blockers, Blocker{Plane: "cp", Reporter: cp.Instance, Reason: ReasonWrongCAID})
			continue
		}
		if cp.BundleCerts != 2 {
			r.Blockers = append(r.Blockers, Blocker{Plane: "cp", Reporter: cp.Instance, Reason: ReasonNotOverlap})
		}
		gens[cp.SignerGen] = true
		authz[cp.AuthzGen] = true
		cpAtT++
	}
	if len(gens) > 1 {
		r.Blockers = append(r.Blockers, Blocker{Plane: "cp", Reason: ReasonGenerationSplit})
	}
	if len(authz) > 1 {
		r.Blockers = append(r.Blockers, Blocker{Plane: "cp", Reason: ReasonAuthzSplit})
	}
	if cpAtT != cfg.ExpectedCP {
		r.Blockers = append(r.Blockers, Blocker{Plane: "cp", Reason: ReasonCountMismatch})
	}

	// (3) Core plane: every core up and HOLDING T. A converged-and-idle core (held==T,
	// age growing because forward-only suppresses re-apply) is converged — age is NOT a
	// staleness signal once held==T, so we don't gate on it here.
	coreAtT := 0
	for _, c := range obs.Core {
		if !c.Up {
			r.Blockers = append(r.Blockers, Blocker{Plane: "core", Reporter: c.Instance, Reason: ReasonUpDown})
			continue
		}
		if c.HeldCAID != T {
			r.Blockers = append(r.Blockers, Blocker{Plane: "core", Reporter: c.Instance, Reason: ReasonWrongCAID})
			continue
		}
		coreAtT++
	}
	if coreAtT != cfg.ExpectedCore {
		r.Blockers = append(r.Blockers, Blocker{Plane: "core", Reason: ReasonCountMismatch})
	}

	// (4) Edge plane. FAIL-CLOSED FLOOR first: an empty/short ExpectedEdges (registry
	// metric drift, a mislabeled scrape, or the edge_registry_total query returning
	// nothing) would otherwise let the per-edge loop run zero times and the edge plane
	// pass vacuously — converging with healthy CP/core and dropping OLD on a fleet that
	// never re-minted. The operator floor turns that into a hard block.
	if len(obs.ExpectedEdges) < cfg.MinEdges {
		r.Blockers = append(r.Blockers, Blocker{Plane: "edge", Reason: ReasonEdgeCountBelowFloor})
	}

	// Every EXPECTED (registry==1, not excluded) edge must be up, live on T, have observed
	// T, have a fresh poll-loop heartbeat, and no FAILED re-mints.
	byID := map[string]EdgeReporter{}
	for _, e := range obs.Edges {
		byID[e.EdgeID] = e
	}
	for _, id := range obs.ExpectedEdges {
		if excluded[id] {
			continue
		}
		e, ok := byID[id]
		if !ok {
			r.Blockers = append(r.Blockers, Blocker{Plane: "edge", Reporter: id, Reason: ReasonNeverScraped})
			continue
		}
		switch {
		case !e.Up:
			r.Blockers = append(r.Blockers, Blocker{Plane: "edge", Reporter: id, Reason: ReasonUpDown})
		case e.LiveCAID != T:
			r.Blockers = append(r.Blockers, Blocker{Plane: "edge", Reporter: id, Reason: ReasonWrongCAID})
		case e.ObservedTarget != T:
			r.Blockers = append(r.Blockers, Blocker{Plane: "edge", Reporter: id, Reason: ReasonTargetNotObserved})
		case !e.RefreshedInWindow:
			r.Blockers = append(r.Blockers, Blocker{Plane: "edge", Reporter: id, Reason: ReasonRefreshStale})
		case e.FailedRemints:
			r.Blockers = append(r.Blockers, Blocker{Plane: "edge", Reporter: id, Reason: ReasonRemintChurn})
		}
	}

	// (5) Live-OLD-leaf veto: ANY edge observed live on a non-target leaf blocks — even
	// one merely registry-disabled but still RUNNING — unless explicitly excluded. The
	// expected-to-converge set (the veto driver) is decoupled from the still-running-and-
	// trusted set (the actual blast radius); registry==0 does NOT silently waive it.
	for _, e := range obs.Edges {
		if excluded[e.EdgeID] {
			continue
		}
		if e.Up && e.LiveCAID != "" && e.LiveCAID != T {
			r.Blockers = append(r.Blockers, Blocker{Plane: "edge", Reporter: e.EdgeID, Reason: ReasonLiveOldLeaf})
		}
	}

	// (6) Revoked-token absence: the probe MUST have run (fail-closed) and the revoked
	// token MUST be rejected (401/403). 2xx ⇒ it can still mint a NEW-CA leaf ⇒ block.
	if !obs.RevokedProbeRan {
		r.Blockers = append(r.Blockers, Blocker{Plane: "revoked", Reason: ReasonRevokedUnverified})
	} else if obs.RevokedProbeStatus != 401 && obs.RevokedProbeStatus != 403 {
		r.Blockers = append(r.Blockers, Blocker{Plane: "revoked", Reason: ReasonRevokedLeafPresent})
	}

	return finalize(r)
}

func finalize(r Result) Result {
	r.Converged = len(r.Blockers) == 0
	return r
}
