package edgecp

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

// Control-plane convergence metrics. These describe the CA the SERVING control plane
// currently signs under and distributes — the authoritative target the fleet (core +
// edges) converges to during a rotation. They are registered on the shared parapet
// registry (prom.Registry()) and served by the CP's /metrics listener (serving process
// only; the run-once bootstrap/rotate Jobs never start the listener).
//
// ca_id is a public-cert SHA-256 fingerprint, never key material. Each ca_id-labelled
// vec is Reset() then Set() on every signer swap so exactly ONE live series exists
// in-process (the per-rotation churn across TSDB retention is bounded by the rotation
// rate, not unbounded). Set atomically under Server.genMu by setSignerMetrics so a
// scrape never tears across the gauges.
var (
	signerFingerprint = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_ca_signer_fingerprint",
		Help:      "Edge CA the serving control plane signs under, by ca_id (value 1).",
	}, []string{"ca_id"})

	signerGeneration = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_ca_signer_generation",
		Help:      "Trust-bundle generation of the serving control-plane signer (value = generation), by ca_id.",
	}, []string{"ca_id"})

	signerBundleCerts = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_ca_bundle_certs",
		Help:      "Number of CA certs in the served bundle (2 during OLD++NEW overlap, else 1), by ca_id.",
	}, []string{"ca_id"})

	signerLoaded = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_ca_signer_loaded",
		Help:      "1 once a signer is loaded (issuance live); 0 while the CP is up but not yet provisioned.",
	})

	targetCAID = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_ca_target_ca_id",
		Help:      "The ca_id the fleet should converge to — the serving control plane's current signer (value 1).",
	}, []string{"ca_id"})

	// signerFloored counts signer swaps rejected by the monotonic generation floor (an
	// out-of-order re-list serving an older cached CA object). A non-zero rate means a
	// rotation is being held back at last-good — it must be scrapeable, not just logged,
	// because the floor turns the always-swap path into a sometimes-skip.
	signerFloored = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "edge_ca_signer_floored_total",
		Help:      "Signer swaps rejected by the monotonic generation floor (older-than-served generation).",
	})

	// signerRVUnparsed is 1 while the CA Secret's resourceVersion is non-numeric (the
	// signer is frozen at last-good and readiness will 503 if none loaded). The k8s
	// contract permits an opaque resourceVersion, so this can be a PERMANENT stuck state
	// — it must be alertable, not a one-shot log line.
	signerRVUnparsed = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_ca_signer_rv_unparsed",
		Help:      "1 when the CA Secret resourceVersion is non-numeric (signer frozen at last-good); 0 when parseable.",
	})

	// activeSignerFP is the fingerprint of the ACTIVE signing cert (what signs new leaves).
	// During an OLD++NEW overlap the bundle ca_id is identical for active=OLD and =NEW, so
	// this is the ONLY signal that distinguishes them — the interlock asserts every CP
	// replica signs under NEW (sigfp == target) before the OLD-drop, proving issued leaves
	// chain to NEW. Reset-then-Set under genMu like the others.
	activeSignerFP = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_ca_active_signer_fp",
		Help:      "The active signing cert fingerprint, by ca_id + sigfp (value 1).",
	}, []string{"ca_id", "sigfp"})

	// signerActiveFlipFailed is 1 when an active=new reload was requested but the candidate
	// signer wouldn't build (fingerprint pin / reordered bundle) — the replica is wedged
	// minting OLD-signed leaves. Without this it surfaces only as an unexplained converge stall.
	signerActiveFlipFailed = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_ca_signer_active_flip_failed",
		Help:      "1 when an active=new signer reload failed to build (replica wedged on OLD signing); 0 otherwise.",
	})

	// issuedUnderSigner is the CP-AUTHORITATIVE issuance ledger: every minted edge leaf by
	// edge_id + the active signer fp. The revoke interlock asserts the REVOKED edge_id has
	// ZERO issuances under NEW across all replicas — a guarantee that does NOT rest on the
	// (forgeable) edge self-report.
	issuedUnderSigner = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "edge_ca_issued_total",
		Help:      "Edge client certs minted, by edge_id + the active signer fp that signed them.",
	}, []string{"edge_id", "sigfp"})
)

var (
	// registryTotal is the EXPECTED-edge reporter set: one series per data-plane edge id
	// in this CP's token registry, value 1 (enabled) or 0 (disabled/blacklisted). The
	// OLD-drop interlock reads label_values(edge_registry_total==1) to discover which
	// edges must converge. A disabled edge flips to 0 and drops from the expected set —
	// but a still-RUNNING disabled edge presenting an OLD leaf is caught by the live-edge
	// gate, not waved through by this.
	registryTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_registry_total",
		Help:      "Edges in this control plane's token registry, by edge_id (1=enabled, 0=disabled).",
	}, []string{"edge_id"})

	// authzGeneration is a deterministic fingerprint of the loaded token registry,
	// IDENTICAL on every replica that loaded the same registry. It is the pre-rotation
	// blacklist-barrier (B0) contract: the interlock confirms every CP replica reports
	// the same value (so a blacklist has converged on all replicas) before a revoke
	// flips the active CA. The hot authz-watch is deferred; today a blacklist requires
	// restart-all-CP, which this value lets the operator verify converged.
	authzGeneration = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_authz_generation",
		Help:      "Deterministic fingerprint of the loaded token registry (replica-identical; the blacklist-barrier signal).",
	})
)

func init() {
	prom.Registry().MustRegister(signerFingerprint, signerGeneration, signerBundleCerts, signerLoaded, targetCAID, signerFloored, signerRVUnparsed, registryTotal, authzGeneration, activeSignerFP, signerActiveFlipFailed, issuedUnderSigner)
}

// recordIssuance ledgers one minted edge leaf under the active signer fp (CP-authoritative).
func recordIssuance(edgeID, signerFP string) {
	issuedUnderSigner.WithLabelValues(edgeID, signerFP).Inc()
}

// SetRegistryMetrics publishes the expected-edge reporter set and the authz-generation
// fingerprint from the loaded token registry. Call once at startup (the registry is
// static today). Only entries with a non-empty id are data-plane edges.
func SetRegistryMetrics(entries map[string]Entry) {
	registryTotal.Reset()
	lines := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.ID == "" {
			continue
		}
		v := 1.0
		d := "0"
		if e.Disabled {
			v, d = 0.0, "1"
		}
		registryTotal.WithLabelValues(e.ID).Set(v)
		lines = append(lines, e.ID+":"+d)
	}
	authzGeneration.Set(registryFingerprint(lines))
}

// registryFingerprint hashes the sorted "id:disabled" lines into a stable float value
// (first 6 bytes of the digest — < 2^48, exactly representable in a float64), so every
// replica loading the same registry reports the identical authz_generation.
func registryFingerprint(lines []string) float64 {
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, ";")))
	return float64(binary.BigEndian.Uint64(append([]byte{0, 0}, sum[:6]...)))
}

// setSignerMetrics records the active signer's ca_id, generation, and bundle size. It
// Reset()s each ca_id vec first so only one live series remains across rotations. Call
// it under Server.genMu (the same critical section that swaps the signer) so all five
// gauges move together and no scrape sees a torn snapshot.
func setSignerMetrics(caID, activeFP string, gen uint64, certCount int) {
	signerFingerprint.Reset()
	signerFingerprint.WithLabelValues(caID).Set(1)
	signerGeneration.Reset()
	signerGeneration.WithLabelValues(caID).Set(float64(gen))
	signerBundleCerts.Reset()
	signerBundleCerts.WithLabelValues(caID).Set(float64(certCount))
	signerLoaded.Set(1)
	// target == the current serving signer's ca_id: the named anchor an operator's
	// convergence PromQL compares the core + edge ca_ids against, with no hardcoded value.
	targetCAID.Reset()
	targetCAID.WithLabelValues(caID).Set(1)
	// the active signing fp — distinguishes active=OLD vs =NEW at an identical bundle ca_id.
	activeSignerFP.Reset()
	if activeFP != "" {
		activeSignerFP.WithLabelValues(caID, activeFP).Set(1)
	}
}
