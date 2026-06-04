package converge

import (
	"testing"
	"time"
)

const T = "target-ca-id"

// converged returns a fully-converged snapshot + config; cases mutate a copy to trip one
// blocker each.
func converged() (Observations, Config) {
	obs := Observations{
		CP: []CPReplica{
			{Instance: "cp-0", Up: true, TargetCAID: T, SignerCAID: T, SignerGen: 100, BundleCerts: 2, AuthzGen: 42},
			{Instance: "cp-1", Up: true, TargetCAID: T, SignerCAID: T, SignerGen: 100, BundleCerts: 2, AuthzGen: 42},
		},
		Core: []CoreReplica{{Instance: "core-0", Up: true, HeldCAID: T}},
		Edges: []EdgeReporter{
			{EdgeID: "e1", Up: true, LiveCAID: T, ObservedTarget: T, RefreshedInWindow: true},
			{EdgeID: "e2", Up: true, LiveCAID: T, ObservedTarget: T, RefreshedInWindow: true},
		},
		ExpectedEdges:      []string{"e1", "e2"},
		RevokedProbeRan:    true,
		RevokedProbeStatus: 401,
	}
	cfg := Config{ExpectedCP: 2, ExpectedCore: 1, MinEdges: 2, Freshness: 5 * time.Minute}
	return obs, cfg
}

func hasBlocker(r Result, reason string) bool {
	for _, b := range r.Blockers {
		if b.Reason == reason {
			return true
		}
	}
	return false
}

func TestEvaluateConverged(t *testing.T) {
	obs, cfg := converged()
	r := Evaluate(obs, cfg, time.Now())
	if !r.Converged {
		t.Fatalf("happy path must converge; blockers=%v", r.Blockers)
	}
	if r.Target != T {
		t.Errorf("target = %q, want %q", r.Target, T)
	}
}

func TestEvaluateBlockers(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Observations, *Config)
		reason string
	}{
		{"cp-target-split", func(o *Observations, _ *Config) { o.CP[1].TargetCAID = "other" }, ReasonCPTargetSplit},
		{"generation-split", func(o *Observations, _ *Config) { o.CP[1].SignerGen = 999 }, ReasonGenerationSplit},
		{"no-target", func(o *Observations, _ *Config) { o.CP[0].TargetCAID, o.CP[1].TargetCAID = "", "" }, ReasonNoTarget},
		{"cp-count", func(_ *Observations, c *Config) { c.ExpectedCP = 3 }, ReasonCountMismatch},
		{"cp-up-down", func(o *Observations, _ *Config) { o.CP[0].Up = false }, ReasonUpDown},
		{"cp-wrong-ca", func(o *Observations, _ *Config) { o.CP[0].SignerCAID = "old" }, ReasonWrongCAID},
		{"not-overlap", func(o *Observations, _ *Config) { o.CP[0].BundleCerts = 1 }, ReasonNotOverlap},
		{"authz-split", func(o *Observations, _ *Config) { o.CP[1].AuthzGen = 99 }, ReasonAuthzSplit},
		{"core-wrong-ca", func(o *Observations, _ *Config) { o.Core[0].HeldCAID = "old" }, ReasonWrongCAID},
		{"core-up-down", func(o *Observations, _ *Config) { o.Core[0].Up = false }, ReasonUpDown},
		{"edge-never-scraped", func(o *Observations, _ *Config) { o.ExpectedEdges = append(o.ExpectedEdges, "e3") }, ReasonNeverScraped},
		{"edge-target-not-observed", func(o *Observations, _ *Config) { o.Edges[0].ObservedTarget = "old" }, ReasonTargetNotObserved},
		{"edge-refresh-stale", func(o *Observations, _ *Config) { o.Edges[0].RefreshedInWindow = false }, ReasonRefreshStale},
		{"edge-remint-churn", func(o *Observations, _ *Config) { o.Edges[0].FailedRemints = true }, ReasonRemintChurn},
		{"live-old-leaf", func(o *Observations, _ *Config) {
			o.Edges = append(o.Edges, EdgeReporter{EdgeID: "rogue", Up: true, LiveCAID: "old", ObservedTarget: T, RefreshedInWindow: true})
		}, ReasonLiveOldLeaf},
		{"revoked-unverified", func(o *Observations, _ *Config) { o.RevokedProbeRan = false }, ReasonRevokedUnverified},
		{"revoked-leaf-present", func(o *Observations, _ *Config) { o.RevokedProbeStatus = 200 }, ReasonRevokedLeafPresent},
		{"exclude-without-reason", func(_ *Observations, c *Config) { c.Exclude = []ExcludedEdge{{EdgeID: "e1"}} }, "exclude-without-reason"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs, cfg := converged()
			tc.mutate(&obs, &cfg)
			r := Evaluate(obs, cfg, time.Now())
			if r.Converged {
				t.Errorf("%s: must NOT converge", tc.name)
			}
			if !hasBlocker(r, tc.reason) {
				t.Errorf("%s: want blocker %q, got %v", tc.name, tc.reason, r.Blockers)
			}
		})
	}
}

// THE fail-open guard: a registry/scrape drift that empties ExpectedEdges, with healthy
// CP/core, must NOT converge vacuously (the per-edge loop running zero times). The floor
// blocks it.
func TestEvaluateEdgeCountFloorBlocksVacuousConvergence(t *testing.T) {
	obs, cfg := converged()
	obs.ExpectedEdges = nil // registry query came back empty (drift / mislabeled scrape)
	obs.Edges = nil
	r := Evaluate(obs, cfg, time.Now())
	if r.Converged || !hasBlocker(r, ReasonEdgeCountBelowFloor) {
		t.Errorf("empty ExpectedEdges with a floor must block (edge-count-below-floor), got %v", r.Blockers)
	}
}

// MinEdges<=0 is a misconfig — the floor must not be silently disableable.
func TestEvaluateMinEdgesUnsetIsMisconfig(t *testing.T) {
	obs, cfg := converged()
	cfg.MinEdges = 0
	r := Evaluate(obs, cfg, time.Now())
	if r.Converged || !hasBlocker(r, "expected-counts-unset") {
		t.Errorf("MinEdges<=0 must block as a misconfig, got %v", r.Blockers)
	}
}

func TestEvaluateExpectedSetEmpty(t *testing.T) {
	r := Evaluate(Observations{}, Config{ExpectedCP: 1, ExpectedCore: 1}, time.Now())
	if r.Converged || !hasBlocker(r, ReasonExpectedSetEmpty) {
		t.Errorf("empty observations must block with expected-set-empty, got %v", r.Blockers)
	}
}

// A reason-bearing exclude waives the convergence veto for a decommissioned edge (a
// never-scraped expected edge), and the waiver is echoed in the verdict.
func TestEvaluateExcludeWaivesVeto(t *testing.T) {
	obs, cfg := converged()
	obs.ExpectedEdges = append(obs.ExpectedEdges, "e3-gone") // would be never-scraped
	cfg.Exclude = []ExcludedEdge{{EdgeID: "e3-gone", Reason: "decommissioned 2026-06-04"}}
	r := Evaluate(obs, cfg, time.Now())
	if !r.Converged {
		t.Errorf("a reason-bearing exclude must waive the veto; blockers=%v", r.Blockers)
	}
	if len(r.Excluded) != 1 || r.Excluded[0].EdgeID != "e3-gone" {
		t.Error("the applied exclusion must be echoed in Result for the audit trail")
	}
}

// ---- Active-flip drop checkpoint (Config.ExpectedActiveSignerFP pinned) ----

const (
	newFP = "new-signer-fp"
	oldFP = "old-signer-fp"
)

// dropConverged is a fully-converged snapshot at the DESTRUCTIVE drop checkpoint: every
// CP replica + good edge is NEW-signed, the blacklist has converged (authz gen matches
// the pin), and the revoked edge — still running on its last OLD-signed leaf — is exempt.
func dropConverged() (Observations, Config) {
	obs, cfg := converged()
	for i := range obs.CP {
		obs.CP[i].ActiveSignerFP = newFP
	}
	for i := range obs.Edges {
		obs.Edges[i].LiveSignerFP = newFP
		obs.Edges[i].ObservedSignerFP = newFP
	}
	// The revoked edge: registry-dropped (not in ExpectedEdges), still live on its OLD-signed
	// leaf at the converged bundle ca_id T. It is the intended casualty — must not block.
	obs.Edges = append(obs.Edges, EdgeReporter{
		EdgeID: "revoked-x", Up: true, LiveCAID: T, ObservedTarget: T, RefreshedInWindow: true,
		LiveSignerFP: oldFP, ObservedSignerFP: oldFP,
	})
	cfg.ExpectedTargetCAID = T
	cfg.ExpectedActiveSignerFP = newFP
	cfg.ExpectedAuthzGen = 42 // matches the fixture's AuthzGen
	cfg.RevokedEdgeID = "revoked-x"
	return obs, cfg
}

func TestEvaluateDropConverged(t *testing.T) {
	obs, cfg := dropConverged()
	r := Evaluate(obs, cfg, time.Now())
	if !r.Converged {
		t.Fatalf("drop checkpoint must converge with everyone NEW-signed + revoked exempt; blockers=%v", r.Blockers)
	}
}

func TestEvaluateDropBlockers(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Observations, *Config)
		reason string
	}{
		{"target-mismatch", func(_ *Observations, c *Config) { c.ExpectedTargetCAID = "other" }, ReasonTargetMismatch},
		{"authz-pin-unset", func(_ *Observations, c *Config) { c.ExpectedAuthzGen = 0 }, ReasonAuthzPinUnset},
		{"cp-not-new-signer", func(o *Observations, _ *Config) { o.CP[0].ActiveSignerFP = oldFP }, ReasonCPNotNewSigner},
		{"cp-signer-split", func(o *Observations, _ *Config) { o.CP[1].ActiveSignerFP = "third-fp" }, ReasonCPSignerSplit},
		{"authz-not-converged", func(o *Observations, _ *Config) { o.CP[0].AuthzGen, o.CP[1].AuthzGen = 99, 99 }, ReasonAuthzNotConverged},
		{"revoked-issued-under-new", func(o *Observations, _ *Config) { o.CP[0].RevokedIssuedUnderNew = 3 }, ReasonRevokedIssuedUnderNew},
		{"edge-old-signer", func(o *Observations, _ *Config) { o.Edges[0].LiveSignerFP = oldFP }, ReasonEdgeOldSigner},
		{"edge-signer-unresolved", func(o *Observations, _ *Config) { o.Edges[0].LiveSignerFP = "" }, ReasonEdgeSignerUnresolved},
		{"edge-signer-not-observed", func(o *Observations, _ *Config) { o.Edges[0].ObservedSignerFP = "stale" }, ReasonEdgeSignerNotObserved},
		{"live-old-signer", func(o *Observations, _ *Config) {
			o.Edges = append(o.Edges, EdgeReporter{EdgeID: "rogue", Up: true, LiveCAID: T, ObservedTarget: T, RefreshedInWindow: true, LiveSignerFP: oldFP, ObservedSignerFP: newFP})
		}, ReasonLiveOldSigner},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs, cfg := dropConverged()
			tc.mutate(&obs, &cfg)
			r := Evaluate(obs, cfg, time.Now())
			if r.Converged {
				t.Errorf("%s: must NOT converge", tc.name)
			}
			if !hasBlocker(r, tc.reason) {
				t.Errorf("%s: want blocker %q, got %v", tc.name, tc.reason, r.Blockers)
			}
		})
	}
}

// The revoked edge, still live on an OLD-signed leaf, must NOT trip the live-OLD vetoes —
// severing exactly it is the drop's purpose. Without the exemption the revoke deadlocks.
func TestEvaluateDropRevokedEdgeExempt(t *testing.T) {
	obs, cfg := dropConverged()
	r := Evaluate(obs, cfg, time.Now())
	if hasBlocker(r, ReasonLiveOldSigner) || hasBlocker(r, ReasonLiveOldLeaf) {
		t.Errorf("the revoked edge (live on OLD) must be exempt from the live-OLD vetoes, got %v", r.Blockers)
	}
	// Sanity: without naming it as revoked, the SAME edge DOES veto (proves the exemption is
	// load-bearing, not that the leaf is invisible).
	cfg.RevokedEdgeID = ""
	if r := Evaluate(obs, cfg, time.Now()); !hasBlocker(r, ReasonLiveOldSigner) {
		t.Error("an unexempted edge live on OLD must trip live-old-signer")
	}
}

// The widen checkpoint (no fp pin) must IGNORE the active-flip signals — a fleet still on
// OLD-signed leaves is correctly converged for the pre-flip barrier.
func TestEvaluateWidenCheckpointIgnoresSignerFP(t *testing.T) {
	obs, cfg := converged() // no ExpectedActiveSignerFP
	for i := range obs.Edges {
		obs.Edges[i].LiveSignerFP = oldFP // still OLD-signed — fine pre-flip
	}
	r := Evaluate(obs, cfg, time.Now())
	if !r.Converged {
		t.Errorf("the widen checkpoint must not gate on signer fp; blockers=%v", r.Blockers)
	}
}

// A still-RUNNING blacklisted edge (live on OLD, registry-dropped from ExpectedEdges)
// must STILL block — registry==0 does not silently waive a live OLD leaf.
func TestEvaluateRunningBlacklistedEdgeStillBlocks(t *testing.T) {
	obs, cfg := converged()
	// "ghost" is NOT in ExpectedEdges (registry-disabled) but is observed live on OLD.
	obs.Edges = append(obs.Edges, EdgeReporter{EdgeID: "ghost", Up: true, LiveCAID: "old-ca", ObservedTarget: T, RefreshedInWindow: true})
	r := Evaluate(obs, cfg, time.Now())
	if r.Converged || !hasBlocker(r, ReasonLiveOldLeaf) {
		t.Errorf("a running blacklisted edge on OLD must block (live-old-leaf), got %v", r.Blockers)
	}
}
