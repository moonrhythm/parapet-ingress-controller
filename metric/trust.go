package metric

import (
	"sync/atomic"
	"time"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

// Core (controller) trust-convergence metrics. The core pulls the edge-CA trust
// bundle from the control plane and decides per-request trust; these expose which
// ca_id/generation it trusts, how stale that is, why a bundle was rejected, and which
// path authorized each request — the core side of the convergence board. All are on
// the shared parapet registry (served on the existing :9187), pure instrumentation.
var (
	trustBundleGeneration = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "trust_bundle_generation",
		Help:      "Generation of the edge trust bundle the core currently trusts (value = generation), by ca_id.",
	}, []string{"ca_id"})

	trustApply = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "trust_apply_total",
		Help:      "Trust-bundle apply attempts by result (applied|rollback_rejected|parse_rejected|empty_rejected).",
	}, []string{"result"})

	trustFetchFailed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "trust_fetch_failed_total",
		Help:      "Trust-bundle fetches that failed to reach/decode the control plane (distinct from reached-but-rejected).",
	})

	trustSource = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prom.Namespace,
		Name:      "trust_source_total",
		Help:      "Per-request trust decision by source (cidr|verified-chain|none).",
	}, []string{"source"})

	// lastApply is the unix-nanos timestamp of the last successful apply, read at scrape
	// time by the trust_bundle_age_seconds GaugeFunc (zero steady-state cost, no ticker).
	lastApply atomic.Int64

	// Pre-materialized bounded-enum handles: the hot-path helpers do a bare Inc() with
	// zero label resolution and zero locking (mirrors metric/reload.go).
	trustApplyHandles = map[string]prometheus.Counter{}

	// trustSourceCounters is indexed by TrustSrc (not a string-keyed map) so the
	// per-request TrustSource is a bare array load + atomic add — no string hash, no
	// map lookup. Populated once in init().
	trustSourceCounters [numTrustSrc]prometheus.Counter
)

// TrustSrc is the per-request trust decision. It indexes trustSourceCounters, so the
// hot path avoids a string hash and is type-safe (a bad value can't compile, unlike a
// stringly-typed label that would silently no-op on a typo).
type TrustSrc uint8

const (
	TrustSrcNone TrustSrc = iota
	TrustSrcCIDR
	TrustSrcVerifiedChain
	numTrustSrc
)

func init() {
	bundleAge := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: prom.Namespace,
		Name:      "trust_bundle_age_seconds",
		Help:      "Seconds since the core last applied an edge trust bundle (0 before the first apply). Rising fleet-wide = convergence stalled.",
	}, func() float64 {
		ns := lastApply.Load()
		if ns == 0 {
			return 0
		}
		return time.Since(time.Unix(0, ns)).Seconds()
	})
	prom.Registry().MustRegister(trustBundleGeneration, trustApply, trustFetchFailed, trustSource, bundleAge)

	for _, r := range []string{"applied", "rollback_rejected", "parse_rejected", "empty_rejected"} {
		trustApplyHandles[r], _ = trustApply.GetMetricWith(prometheus.Labels{"result": r})
	}
	trustSourceCounters[TrustSrcNone], _ = trustSource.GetMetricWith(prometheus.Labels{"source": "none"})
	trustSourceCounters[TrustSrcCIDR], _ = trustSource.GetMetricWith(prometheus.Labels{"source": "cidr"})
	trustSourceCounters[TrustSrcVerifiedChain], _ = trustSource.GetMetricWith(prometheus.Labels{"source": "verified-chain"})
}

// TrustApply counts a bundle apply attempt by result. rollback_rejected is the
// anti-replay security signal — kept distinguishable from the other rejections.
func TrustApply(result string) {
	if h := trustApplyHandles[result]; h != nil {
		h.Inc()
	}
}

// TrustBundleApplied records a successful apply: stamps the age clock and sets the
// trusted generation for ca_id (Reset()-then-Set keeps exactly one live series across
// rotations). Called only from the single trust.Manager.Run goroutine.
func TrustBundleApplied(caID string, generation uint64) {
	lastApply.Store(time.Now().UnixNano()) // age clock is correct regardless of id
	trustBundleGeneration.Reset()
	// Guard the empty id (a CP that served no fingerprint) so we never mint a
	// ca_id="" series — symmetric with the edge helper. Trust itself is unaffected:
	// the core trusts the CA pool, not the id, so the bundle still applied.
	if caID != "" {
		trustBundleGeneration.WithLabelValues(caID).Set(float64(generation))
	}
}

// TrustFetchFailed counts a failed trust-bundle fetch (couldn't reach/decode the CP).
func TrustFetchFailed() { trustFetchFailed.Inc() }

// TrustSource counts one per-request trust decision. Hot-path: a bare array index +
// atomic add — no lock, no label resolution, no map hash.
func TrustSource(s TrustSrc) {
	trustSourceCounters[s].Inc()
}
