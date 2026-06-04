package edgecp

import (
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
)

func init() {
	prom.Registry().MustRegister(signerFingerprint, signerGeneration, signerBundleCerts, signerLoaded, targetCAID)
}

// setSignerMetrics records the active signer's ca_id, generation, and bundle size. It
// Reset()s each ca_id vec first so only one live series remains across rotations. Call
// it under Server.genMu (the same critical section that swaps the signer) so all five
// gauges move together and no scrape sees a torn snapshot.
func setSignerMetrics(caID string, gen uint64, certCount int) {
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
}
