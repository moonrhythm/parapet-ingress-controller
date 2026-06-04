package edge

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"
)

// RemintConfig tunes the data-plane client-cert re-mint coordinator. Zero fields get
// sane floors in NewRemintCoordinator (the caller passes interval-derived values).
type RemintConfig struct {
	Jitter        time.Duration // full-jitter [0,Jitter] before EACH mint, to spread the fleet (default 60s)
	BackoffBase   time.Duration // exponential backoff base on a non-ok mint (default 2s)
	BackoffMax    time.Duration // backoff cap (default 300s)
	Cooldown      time.Duration // breaker-open cooldown (default 5*BackoffMax)
	BreakerK      int           // consecutive reactive no-flip ok-mints before the reactive breaker opens (default 3)
	ProactiveJ    int           // proactive ok-mints that don't reach target before the proactive breaker opens (default 5)
	RenewFraction float64       // remaining-life renewal: renew when remaining <= fraction of the leaf's own lifetime (default 0.66)
}

// RemintCoordinator is the single owner of every data-plane client-cert re-mint path
// (proactive on a ca_id flip, reactive on a core cert-reject, timer on remaining-life).
// It enforces per-edge single-flight, full jitter, exponential backoff, Retry-After,
// and two independent circuit-breakers (reactive + proactive). A nil *RemintCoordinator
// is a valid no-op receiver, so non-mTLS edges call the same code with no effect.
type RemintCoordinator struct {
	cp    *CpClient
	store *ClientCertStore
	cfg   RemintConfig

	mu                  sync.Mutex
	inFlight            bool
	backoff             time.Duration
	reactiveNoFlip      int
	reactiveBreakerEnd  time.Time
	proactiveNoConverge int
	proactiveBreakerEnd time.Time
	lastTarget          string // last observed CP target ca_id (the proactive convergence yardstick)
	lastTargetFP        string // last observed CP active signer fp (the active=OLD→NEW flip yardstick)
}

func NewRemintCoordinator(cp *CpClient, store *ClientCertStore, cfg RemintConfig) *RemintCoordinator {
	if cfg.Jitter <= 0 {
		cfg.Jitter = 60 * time.Second
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 2 * time.Second
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 300 * time.Second
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 5 * cfg.BackoffMax
	}
	if cfg.BreakerK <= 0 {
		cfg.BreakerK = 3
	}
	if cfg.ProactiveJ <= 0 {
		cfg.ProactiveJ = 5
	}
	if cfg.RenewFraction <= 0 || cfg.RenewFraction >= 1 {
		cfg.RenewFraction = 0.66
	}
	return &RemintCoordinator{cp: cp, store: store, cfg: cfg, backoff: cfg.BackoffBase}
}

// Observe drives the PROACTIVE path: it compares the CP target TUPLE (ca_id + active
// signer fp) against the edge's OWN HELD-LEAF tuple (never against a previous
// observation, so a mid-rotation boot re-mints on first poll) and triggers a re-mint on
// a mismatch on EITHER axis:
//   - ca_id mismatch: a CA-set rotation — new trust material to mint against.
//   - signer_fp mismatch: an active=OLD→NEW flip at an UNCHANGED bundle ca_id (both
//     active states append the same OLD++NEW bundle, so ca_id can't see it). This is the
//     load-bearing re-mint that re-chains the leaf to NEW so it survives the OLD-drop.
//
// Each axis is fail-static on "": target=="" (old CP / no signer) returns outright; a ""
// held or target value on an axis is "unknown" and never triggers on that axis (avoids an
// infinite hot-loop). Safe to call from the public-TLS handshake path (Trigger is
// non-blocking).
func (c *RemintCoordinator) Observe(target, targetFP string) {
	if c == nil || target == "" {
		return
	}
	setObservedTarget(target)
	setObservedSignerFP(targetFP)
	liveCA := c.store.CAID()
	liveFP := c.store.SignerFP()
	c.mu.Lock()
	c.lastTarget = target
	c.lastTargetFP = targetFP
	c.mu.Unlock()
	caMismatch := liveCA != "" && target != liveCA
	fpMismatch := targetFP != "" && liveFP != "" && targetFP != liveFP
	if !caMismatch && !fpMismatch {
		return // unknown held value, or already converged on both axes
	}
	c.Trigger("proactive")
}

// Trigger requests a re-mint. It is NON-BLOCKING on every path: if a mint is already in
// flight it returns immediately (a dropped trigger is re-derived by the next poll's
// held-vs-target re-check). Reactive triggers are dropped while the reactive breaker is
// open; proactive triggers bypass the reactive cooldown but honor the proactive breaker.
func (c *RemintCoordinator) Trigger(trigger string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inFlight {
		return
	}
	now := time.Now()
	if trigger == "reactive" && now.Before(c.reactiveBreakerEnd) {
		return
	}
	if trigger == "proactive" && now.Before(c.proactiveBreakerEnd) {
		return
	}
	c.inFlight = true
	go func() {
		// Clear inFlight via defer + recover so a panic in the mint can NEVER strand the
		// single-flight flag (which would brick EVERY re-mint path forever). One bad mint
		// self-heals on the next trigger instead of wedging or crashing the edge.
		defer func() {
			if r := recover(); r != nil {
				slog.Error("edge: re-mint panicked; recovered", "panic", r, "trigger", trigger)
			}
			c.mu.Lock()
			c.inFlight = false
			c.mu.Unlock()
		}()
		c.runOnce(trigger)
	}()
}

// runOnce executes one mint: jitter → mint → classify (converge/flip/breaker/backoff).
// It is synchronous and does NOT manage inFlight (the Trigger goroutine owns that) —
// tests drive it directly for deterministic breaker assertions. The two breakers are
// scored INDEPENDENTLY, because reaching the CP target is NOT evidence a reactive
// core-reject is resolved (the core may still reject due to its own ClientCAs lag):
//   - ok + ca_id flipped (any trigger): new trust material → reset the reactive breaker.
//   - ok + reactive + NO flip: futile (CP serves the same bundle; re-minting can't fix a
//     core reject) → reactiveNoFlip++ → open the reactive breaker at K.
//   - ok + proactive + reached target: convergence → reset the proactive breaker; else
//     proactiveNoConverge++ → open at J (a real-but-unreachable target isn't infinite).
//   - non-ok: transient (CP outage / saturation) → exponential backoff, honor
//     Retry-After; NEVER breaker evidence (must keep retrying a rejected OLD leaf).
func (c *RemintCoordinator) runOnce(trigger string) {
	c.mu.Lock()
	target := c.lastTarget
	targetFP := c.lastTargetFP
	backoff := c.backoff
	c.mu.Unlock()

	beforeCA, beforeFP := c.store.CAID(), c.store.SignerFP()
	if j := fullJitter(c.cfg.Jitter); j > 0 {
		time.Sleep(j)
	}
	result, retryAfter := RefreshEdgeCertOnce(c.cp, c.store, trigger)
	afterCA, afterFP := c.store.CAID(), c.store.SignerFP()

	var openedReactive, openedProactive bool
	var sleepFor time.Duration
	c.mu.Lock()
	switch {
	case result == "ok":
		c.backoff = c.cfg.BackoffBase // any successful mint clears the backoff
		// "flipped" = the leaf material actually changed on EITHER axis (a CA-set rotation
		// OR an active=OLD→NEW re-chain at an unchanged bundle ca_id). Both are real new
		// trust material, so both reset the reactive breaker.
		flipped := afterCA != beforeCA || afterFP != beforeFP

		// Reactive breaker: keyed on whether the leaf material actually changed.
		if flipped {
			c.reactiveNoFlip = 0
			c.reactiveBreakerEnd = time.Time{}
		} else if trigger == "reactive" {
			c.reactiveNoFlip++
			if c.reactiveNoFlip >= c.cfg.BreakerK {
				c.reactiveBreakerEnd = time.Now().Add(c.cfg.Cooldown)
				openedReactive = true
			}
		}

		// Proactive breaker: keyed on whether the mint reached the OBSERVED target TUPLE —
		// the ca_id AND (when known) the active signer fp. An unchanged ca_id with the fp
		// still on OLD is NOT converged, so the active-flip re-mint isn't scored as success.
		if trigger == "proactive" {
			fpConverged := targetFP == "" || afterFP == targetFP
			if target != "" && afterCA == target && fpConverged {
				c.proactiveNoConverge = 0
				c.proactiveBreakerEnd = time.Time{}
			} else {
				c.proactiveNoConverge++
				if c.proactiveNoConverge >= c.cfg.ProactiveJ {
					c.proactiveBreakerEnd = time.Now().Add(c.cfg.Cooldown)
					openedProactive = true
				}
			}
		}
	default:
		c.backoff = minDur(backoff*2, c.cfg.BackoffMax)
		sleepFor = chooseSleep(backoff, retryAfter)
	}
	c.mu.Unlock()

	if openedReactive {
		remint("breaker_open", "reactive")
		slog.Warn("edge: reactive re-mint breaker OPEN — re-mints aren't changing ca_id (a core-side reject re-minting can't fix); cooling down",
			"consecutive", c.cfg.BreakerK, "cooldown", c.cfg.Cooldown)
	}
	if openedProactive {
		remint("breaker_open", "proactive")
		slog.Warn("edge: proactive re-mint breaker OPEN — mints not reaching the observed target; cooling down",
			"consecutive", c.cfg.ProactiveJ, "target", target, "cooldown", c.cfg.Cooldown)
	}

	if sleepFor > 0 {
		time.Sleep(sleepFor + fullJitter(c.cfg.BackoffBase))
	}
}

// MaybeRenew triggers a "timer" re-mint when no cert is held yet, or the live leaf is
// within its remaining-life renewal window — remaining <= RenewFraction of the cert's
// OWN lifetime (NotAfter-NotBefore), so it needs no knowledge of the CP's TTL and the
// renewal floor scales with whatever TTL the CP issues. This is the absolute floor that
// converges even an edge that observes no ca_id signal at all, before its OLD leaf
// could expire.
func (c *RemintCoordinator) MaybeRenew() {
	if c == nil {
		return
	}
	nb, na, ok := c.store.Validity()
	if !ok {
		c.Trigger("timer") // nothing held yet (startup mint may have failed)
		return
	}
	lifetime := na.Sub(nb)
	if lifetime <= 0 {
		return
	}
	if time.Until(na) <= time.Duration(c.cfg.RenewFraction*float64(lifetime)) {
		c.Trigger("timer")
	}
}

// fullJitter returns a uniformly random duration in [0, d). 0 for d<=0.
func fullJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d)))
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// chooseSleep picks the backoff delay on a non-ok mint: the CP's Retry-After when it
// exceeds our own backoff (so the fleet honors the signer's backpressure), else backoff.
func chooseSleep(backoff, retryAfter time.Duration) time.Duration {
	if retryAfter > backoff {
		return retryAfter
	}
	return backoff
}

// sleepCtx sleeps for d or until ctx is done; returns false if ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
