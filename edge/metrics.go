package edge

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

// Edge data-plane convergence metrics: which CA set issued the edge's LIVE client
// leaf (its ca_id), when that leaf expires, whether the re-mint loop is healthy, and a
// poll-liveness counter. During a rotation the edge's ca_id LAGS the control-plane
// target until the edge re-mints — so this is the per-edge convergence/re-mint progress
// indicator the OLD-drop interlock reads. Registered on the shared parapet registry,
// served on the edge's existing :9187. Pure instrumentation.
//
// Every series carries an edge_id label (the process's STABLE logical identity, from
// EDGE_ID — matching the CP token registry id), so the interlock joins per-edge by a
// reschedule-stable key, not the ephemeral pod/instance. The ca_id-labelled gauges are
// Reset() then Set() on each swap, so exactly one live series per process. ca_id is a
// public-cert fingerprint, never key material.
var (
	edgeClientCertCAID = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_clientcert_ca_id",
		Help:      "CA set that issued the edge's live data-plane client leaf, by ca_id (value 1).",
	}, []string{"ca_id", "edge_id"})

	edgeClientCertNotAfter = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_clientcert_not_after_seconds",
		Help:      "Expiry (unix seconds) of the edge's live data-plane client leaf, by ca_id.",
	}, []string{"ca_id", "edge_id"})

	edgeClientCertLoaded = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_clientcert_loaded",
		Help:      "1 once the edge holds a usable data-plane client cert, else 0.",
	}, []string{"edge_id"})

	edgeRemint = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "edge_clientcert_remint_total",
		Help:      "Edge data-plane cert re-mint attempts by result (ok|keygen_fail|csr_fail|fetch_fail|marshal_fail|store_fail|breaker_open) and trigger (proactive|reactive|timer).",
	}, []string{"result", "trigger", "edge_id"})

	// edgeCPTargetCAID is the edge-OBSERVED CP target ca_id (from the X-Parapet-CA-Id
	// signal). The OLD-drop convergence interlock compares this against the live
	// edge_clientcert_ca_id; equal ⇒ this edge has converged.
	edgeCPTargetCAID = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_cp_target_ca_id",
		Help:      "CP target ca_id the edge last observed (value 1).",
	}, []string{"ca_id", "edge_id"})

	// edgeRefresh is bumped on EVERY successful CP poll (a /v1/certs fetch or the
	// trust-bundle read), regardless of whether ca_id changed. It is the INDEPENDENT
	// liveness signal: the ca_id/target gauges are Reset-then-Set only when something
	// changes, so a wedged poll loop would freeze them at the target while up==1 stays
	// fresh — a frozen edge could then false-green. The interlock gates on
	// increase(edge_refresh_total[Freshness]) >= 1 to prove the loop actually ran.
	edgeRefresh = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "edge_refresh_total",
		Help:      "Successful control-plane polls (proves the refresh loop is alive, independent of ca_id change).",
	}, []string{"edge_id"})
)

func init() {
	prom.Registry().MustRegister(edgeClientCertCAID, edgeClientCertNotAfter, edgeClientCertLoaded, edgeRemint, edgeCPTargetCAID, edgeRefresh)
}

// edgeID is the process's logical identity, stamped on every metric. Defaults to
// "unknown" so a series is NEVER edge_id="" (which would shadow another edge in the
// interlock join). Set once at startup via SetEdgeID.
var edgeID = "unknown"

// SetEdgeID stamps the process's logical edge identity (EDGE_ID) onto every edge
// convergence metric. Call once before serving. An empty id is ignored (keeps the
// "unknown" default — the edge binary refuses to start without EDGE_ID when mTLS is on).
func SetEdgeID(id string) {
	if id != "" {
		edgeID = id
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
		edgeClientCertCAID.WithLabelValues(caID, edgeID).Set(1)
		edgeClientCertNotAfter.WithLabelValues(caID, edgeID).Set(float64(notAfterUnix))
	}
	edgeClientCertLoaded.WithLabelValues(edgeID).Set(1)
}

// remint counts one re-mint attempt by result and trigger. Re-mints are infrequent
// (per rotation / renewal, not per request), so resolving the label here is fine.
func remint(result, trigger string) {
	edgeRemint.WithLabelValues(result, trigger, edgeID).Inc()
}

// setObservedTarget records the CP target ca_id the edge last observed (Reset-then-Set,
// one live series). "" (no signal) clears it.
func setObservedTarget(caID string) {
	edgeCPTargetCAID.Reset()
	if caID != "" {
		edgeCPTargetCAID.WithLabelValues(caID, edgeID).Set(1)
	}
}

// edgeRefreshOK records one successful CP poll (the liveness heartbeat).
func edgeRefreshOK() {
	edgeRefresh.WithLabelValues(edgeID).Inc()
}
