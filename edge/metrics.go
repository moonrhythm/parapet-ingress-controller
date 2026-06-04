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
		Help:      "Edge data-plane cert re-mint attempts by result (ok|keygen_fail|csr_fail|fetch_fail|marshal_fail|store_fail).",
	}, []string{"result"})

	edgeRemintHandles = map[string]prometheus.Counter{}
)

func init() {
	prom.Registry().MustRegister(edgeClientCertCAID, edgeClientCertNotAfter, edgeClientCertLoaded, edgeRemint)
	for _, r := range []string{"ok", "keygen_fail", "csr_fail", "fetch_fail", "marshal_fail", "store_fail"} {
		edgeRemintHandles[r], _ = edgeRemint.GetMetricWith(prometheus.Labels{"result": r})
	}
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

// remint counts one re-mint attempt by result (bare Inc on a pre-materialized handle).
func remint(result string) {
	if h := edgeRemintHandles[result]; h != nil {
		h.Inc()
	}
}
