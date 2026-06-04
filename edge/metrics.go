package edge

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

// Edge data-plane convergence metrics: which CA set issued the edge's LIVE client
// leaf (its ca_id), when that leaf expires, and whether the re-mint loop is healthy.
// During a rotation the edge's ca_id LAGS the control-plane target until the edge
// re-mints (it then matches, because Sign() appends the full served bundle to the
// leaf) — so this is the per-edge convergence/re-mint progress indicator. Registered on
// the shared parapet registry, served on the edge's existing :9187. Pure instrumentation.
//
// The ca_id-labelled gauges are Reset() then Set() on each swap, so exactly one live
// series exists per process. ca_id is a public-cert fingerprint, never key material.
var (
	edgeClientCertCAID = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_clientcert_ca_id",
		Help:      "CA set that issued the edge's live data-plane client leaf, by ca_id (value 1).",
	}, []string{"ca_id"})

	edgeClientCertNotAfter = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_clientcert_not_after_seconds",
		Help:      "Expiry (unix seconds) of the edge's live data-plane client leaf, by ca_id.",
	}, []string{"ca_id"})

	edgeClientCertLoaded = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_clientcert_loaded",
		Help:      "1 once the edge holds a usable data-plane client cert, else 0.",
	})

	edgeRemint = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "edge_clientcert_remint_total",
		Help:      "Edge data-plane cert re-mint attempts by result (ok|keygen_fail|csr_fail|fetch_fail|marshal_fail|store_fail|breaker_open) and trigger (proactive|reactive|timer).",
	}, []string{"result", "trigger"})

	// edgeCPTargetCAID is the edge-OBSERVED CP target ca_id (from the X-Parapet-CA-Id
	// signal). The OLD-drop convergence interlock compares this against the live
	// edge_clientcert_ca_id; equal ⇒ this edge has converged.
	edgeCPTargetCAID = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_cp_target_ca_id",
		Help:      "CP target ca_id the edge last observed (value 1).",
	}, []string{"ca_id"})
)

func init() {
	prom.Registry().MustRegister(edgeClientCertCAID, edgeClientCertNotAfter, edgeClientCertLoaded, edgeRemint, edgeCPTargetCAID)
}

// setClientCertMetrics records the live leaf's ca_id and expiry (Reset()-then-Set so
// only one ca_id series survives a rotation) and marks the cert loaded. An empty caID
// (chain too short to carry a CA block) sets only loaded, leaving the ca_id vecs clear.
// Called only from the single ClientCertStore.Update writer (the re-mint loop).
func setClientCertMetrics(caID string, notAfterUnix int64) {
	edgeClientCertCAID.Reset()
	edgeClientCertNotAfter.Reset()
	if caID != "" {
		edgeClientCertCAID.WithLabelValues(caID).Set(1)
		edgeClientCertNotAfter.WithLabelValues(caID).Set(float64(notAfterUnix))
	}
	edgeClientCertLoaded.Set(1)
}

// remint counts one re-mint attempt by result and trigger. Re-mints are infrequent
// (per rotation / renewal, not per request), so resolving the label here is fine.
func remint(result, trigger string) {
	edgeRemint.WithLabelValues(result, trigger).Inc()
}

// setObservedTarget records the CP target ca_id the edge last observed (Reset-then-Set,
// one live series). "" (no signal) clears it.
func setObservedTarget(caID string) {
	edgeCPTargetCAID.Reset()
	if caID != "" {
		edgeCPTargetCAID.WithLabelValues(caID).Set(1)
	}
}
