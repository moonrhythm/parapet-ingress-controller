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

	// edgeClientCertSignerFP is the fp of the CA that SIGNED the edge's live leaf — the
	// load-bearing proof the leaf chains to NEW (survives the OLD-drop). The ca_id is
	// identical for active=OLD/NEW, so the interlock gates the drop on THIS, not ca_id.
	edgeClientCertSignerFP = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_clientcert_signer_fp",
		Help:      "Fingerprint of the CA that signed the edge's live data-plane leaf (value 1).",
	}, []string{"sigfp", "edge_id"})

	// edgeCPActiveSignerFP is the CP-announced active signing fp the edge last observed —
	// the target the edge re-mints toward (the tuple's other half beside cp_target_ca_id).
	edgeCPActiveSignerFP = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_cp_active_signer_fp",
		Help:      "CP active signing fp the edge last observed (value 1).",
	}, []string{"sigfp", "edge_id"})

	// edgeOnDemand counts serve-all on-demand cert resolutions by result. "hit"/"miss"/"shed"
	// are per-CP-fetch (single-flight leader): hit landed a cert, miss got a 404/error and
	// negative-cached it, shed bailed over the in-flight cap without touching the CP.
	// "suppressed" is per-handshake — a negative-cache short-circuit — so it measures how
	// much repeat-miss load the cache absorbs. A climbing shed/suppressed rate flags an
	// SNI flood or a too-tight cap/TTL.
	edgeOnDemand = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "edge_ondemand_cert_total",
		Help:      "Serve-all on-demand cert resolutions by result (hit|miss|shed|suppressed).",
	}, []string{"result", "edge_id"})

	// --- cache-purge (edge-only) ---

	// edgePurgePoll counts purge polls by result: ok (entries applied/none),
	// flush (cursor-gap flush-all), disabled (CP not distributing), error (fetch failed).
	edgePurgePoll = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "edge_cache_purge_poll_total",
		Help:      "Cache-purge polls by result (ok|flush|disabled|error).",
	}, []string{"result", "edge_id"})

	// edgePurgeEntries counts purge entries applied (cumulative).
	edgePurgeEntries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "edge_cache_purge_entries_total",
		Help:      "Cache-purge journal entries applied by the edge (cumulative).",
	}, []string{"edge_id"})

	// edgePurgeCursor is the last journal seq the edge has applied.
	edgePurgeCursor = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_cache_purge_cursor",
		Help:      "Last cache-purge journal seq applied by the edge.",
	}, []string{"edge_id"})

	// edgePurgeRecords is the current in-memory record count per scope map
	// (host|url|prefix|tag), so an operator can watch the table stay bounded.
	edgePurgeRecords = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_cache_purge_records",
		Help:      "Current cache-purge invalidation-table records, by scope map (host|url|prefix|tag).",
	}, []string{"scope", "edge_id"})

	// edgePurgeFolds is the cumulative count of conservative cap-folds (a map
	// exceeded its cap and was folded into the global epoch). A climbing value flags
	// an undersized cap or an unusually large purge volume.
	edgePurgeFolds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "edge_cache_purge_folds_total",
		Help:      "Cumulative conservative cap-folds of the cache-purge table into the global epoch.",
	}, []string{"edge_id"})

	// edgePurgeReapSweeps counts completed reaper sweeps (each physically reclaims
	// invalidated entries off the serving path).
	edgePurgeReapSweeps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "edge_cache_purge_reap_sweeps_total",
		Help:      "Completed cache-purge reaper sweeps.",
	}, []string{"edge_id"})

	// edgePurgeReapEntries counts entries the reaper physically deleted (cumulative).
	edgePurgeReapEntries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "edge_cache_purge_reap_entries_total",
		Help:      "Cache entries physically reclaimed by the reaper (cumulative).",
	}, []string{"edge_id"})

	// edgeMetricsClientPush counts metrics-push attempts to the control plane. The
	// name deliberately differs from the CP-side parapet_edge_metrics_push_total —
	// this family is itself pushed and merged into the CP's /metrics, and two
	// same-name families with different label sets would merge confusingly.
	edgeMetricsClientPush = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "edge_metrics_client_push_total",
		Help:      "Edge metrics pushes to the control plane by result (ok|gather_fail|push_fail).",
	}, []string{"result", "edge_id"})
)

func init() {
	prom.Registry().MustRegister(edgeClientCertCAID, edgeClientCertNotAfter, edgeClientCertLoaded, edgeRemint, edgeCPTargetCAID, edgeRefresh, edgeClientCertSignerFP, edgeCPActiveSignerFP, edgeOnDemand,
		edgePurgePoll, edgePurgeEntries, edgePurgeCursor, edgePurgeRecords, edgePurgeFolds, edgePurgeReapSweeps, edgePurgeReapEntries, edgeMetricsClientPush)
}

// purgeReap records one completed reaper sweep and the entries it reclaimed.
func purgeReap(reaped int) {
	edgePurgeReapSweeps.WithLabelValues(edgeID).Inc()
	if reaped > 0 {
		edgePurgeReapEntries.WithLabelValues(edgeID).Add(float64(reaped))
	}
}

// metricsPush counts one metrics-push attempt by result.
func metricsPush(result string) { edgeMetricsClientPush.WithLabelValues(result, edgeID).Inc() }

// purgePoll counts one purge poll by result.
func purgePoll(result string) { edgePurgePoll.WithLabelValues(result, edgeID).Inc() }

// purgePollApplied adds n to the applied-entries counter (no-op for n<=0).
func purgePollApplied(n int) {
	if n > 0 {
		edgePurgeEntries.WithLabelValues(edgeID).Add(float64(n))
	}
}

// setPurgeMetrics reflects the table's current state into the gauges (cursor, per-map
// record counts, cap-folds).
func setPurgeMetrics(st PurgeStats) {
	edgePurgeCursor.WithLabelValues(edgeID).Set(float64(st.Cursor))
	edgePurgeRecords.WithLabelValues("host", edgeID).Set(float64(st.HostRecs))
	edgePurgeRecords.WithLabelValues("url", edgeID).Set(float64(st.URLRecs))
	edgePurgeRecords.WithLabelValues("prefix", edgeID).Set(float64(st.PrefixRecs))
	edgePurgeRecords.WithLabelValues("tag", edgeID).Set(float64(st.TagRecs))
	edgePurgeFolds.WithLabelValues(edgeID).Set(float64(st.Folds))
}

// ondemand counts one on-demand cert resolution outcome.
func ondemand(result string) {
	edgeOnDemand.WithLabelValues(result, edgeID).Inc()
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
func setClientCertMetrics(caID, signerFP string, notAfterUnix int64) {
	edgeClientCertCAID.Reset()
	edgeClientCertNotAfter.Reset()
	edgeClientCertSignerFP.Reset()
	if caID != "" {
		edgeClientCertCAID.WithLabelValues(caID, edgeID).Set(1)
		edgeClientCertNotAfter.WithLabelValues(caID, edgeID).Set(float64(notAfterUnix))
	}
	if signerFP != "" {
		edgeClientCertSignerFP.WithLabelValues(signerFP, edgeID).Set(1)
	}
	edgeClientCertLoaded.WithLabelValues(edgeID).Set(1)
}

// setObservedSignerFP records the CP-announced active signing fp the edge last observed.
func setObservedSignerFP(fp string) {
	edgeCPActiveSignerFP.Reset()
	if fp != "" {
		edgeCPActiveSignerFP.WithLabelValues(fp, edgeID).Set(1)
	}
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
