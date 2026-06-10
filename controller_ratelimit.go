package controller

import (
	"context"
	"log/slog"
	"sort"

	"github.com/moonrhythm/parapet"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
	"github.com/moonrhythm/parapet-ingress-controller/ratelimitrule"
)

// rateLimitLabelKey marks a ConfigMap as rate-limit input, mirroring the WAF's
// wafLabelKey model: value "global" is the baseline set (honored only in the
// controller's own namespace), value "zone" is a tenant set whose ID is the
// ConfigMap name. It is a separate label key — and a separate watch — because a
// Kubernetes label selector can't OR two keys; the stores stay separate too.
const rateLimitLabelKey = "parapet.moonrhythm.io/ratelimit"

// InitRateLimit builds the global rate-limit instance and the (empty) zone
// registry. Call after setting RateLimitEnabled and PodNamespace, before
// Watch(). No-op when disabled — disabled means no ConfigMap watch, no mount,
// no per-request work.
func (ctrl *Controller) InitRateLimit() {
	if !ctrl.RateLimitEnabled {
		return
	}
	ctrl.globalRateLimit = &ratelimitrule.Limiter{
		NamePrefix: "global",
		Observe:    observe.RateLimit,
		// Collapse host bucket keys the router doesn't serve: the global set sees
		// every request, including random-Host floods that will 404 at the router.
		KnownHost: ctrl.IsKnownHost,
	}
	empty := map[string]*ratelimitrule.Limiter{}
	ctrl.rlZones.Store(&empty)
	ctrl.rlZoneFingerprints = map[string]string{}
}

// GlobalRateLimit returns the global rate-limit middleware to mount in the
// server chain, or nil when disabled. An enabled limiter with no limits loaded
// is a cheap pass-through (one atomic load).
func (ctrl *Controller) GlobalRateLimit() parapet.Middleware {
	if ctrl.globalRateLimit == nil {
		return nil
	}
	return ctrl.globalRateLimit
}

// LookupRateLimitZone returns the compiled rate-limit set for a zone registry
// key (<namespace>/<name>), or nil if no such zone is loaded. Looked up live on
// the request path so zone edits and new zones propagate without a mux rebuild.
func (ctrl *Controller) LookupRateLimitZone(key string) *ratelimitrule.Limiter {
	m := ctrl.rlZones.Load()
	if m == nil {
		return nil
	}
	return (*m)[key]
}

func (ctrl *Controller) watchRateLimitConfigMaps(ctx context.Context) {
	watchFn := func(ctx context.Context, namespace string) (watch.Interface, error) {
		return k8s.WatchConfigMaps(ctx, namespace, rateLimitLabelKey)
	}
	listFn := func(ctx context.Context, namespace string) ([]v1.ConfigMap, error) {
		return k8s.GetConfigMaps(ctx, namespace, rateLimitLabelKey)
	}
	// Named "ratelimit-configmaps" so its watch/resync log lines are
	// distinguishable from the WAF's "configmaps" loop.
	watchResource(ctx, ctrl.watchNamespace, "ratelimit-configmaps", watchFn, listFn,
		&ctrl.watchedRLConfigMaps,
		func(_ *v1.ConfigMap) { ctrl.reloadRateLimit() },
		func(_ *v1.ConfigMap) { ctrl.reloadRateLimit() },
		ctrl.reloadRateLimit,
	)
}

func (ctrl *Controller) reloadRateLimit() {
	ctrl.reloadRateLimitDebounce.Call()
}

// reloadRateLimitDebounced rebuilds the global limit set and the zone registry
// from the watched ConfigMaps. Like the WAF reload it never touches ctrl.mux —
// a limit edit is a SetLimits + registry swap. SetLimits is all-or-nothing, so
// bad config keeps the last-good set; unchanged inputs (fingerprint match) are
// skipped entirely, which for rate limits also preserves live counters; and a
// changed set carries over counters for limits whose shaping config didn't
// move (SetLimits' per-limit reuse).
func (ctrl *Controller) reloadRateLimitDebounced() {
	if !ctrl.RateLimitEnabled || ctrl.globalRateLimit == nil {
		return
	}
	// Serialize the whole pass: the debounce can fire two passes concurrently
	// (same hazard as wafReloadMu), and the fingerprint string + map below are a
	// read-modify-write that must be atomic across the pass.
	ctrl.rlReloadMu.Lock()
	defer ctrl.rlReloadMu.Unlock()

	defer func() {
		if err := recover(); err != nil {
			slog.Error("reload ratelimit failed", "error", err)
		}
	}()

	var globalCMs []*v1.ConfigMap
	zoneDocs := map[string][]string{}

	ctrl.watchedRLConfigMaps.Range(func(_, value any) bool {
		cm := value.(*v1.ConfigMap)
		role := cm.Labels[rateLimitLabelKey]
		// Refuse a ConfigMap labeled for BOTH features (one ConfigMap per
		// feature, by policy): both reloaders would consume all its data values,
		// and the lenient YAML parsers cross-parse the other feature's documents
		// to zero entries silently — a both-labeled ConfigMap would quietly feed
		// each side an empty/garbage set instead of erroring. Gated on a
		// recognized ratelimit role because the fs backend ignores label
		// selectors, so this store also holds WAF-only ConfigMaps there — those
		// must fall through silently, not warn.
		if role == roleGlobal || role == roleZone {
			if _, alsoWAF := cm.Labels[wafLabelKey]; alsoWAF {
				slog.Warn("ratelimit: ignoring configmap that also carries the waf label; use one configmap per feature",
					"configmap", cm.Namespace+"/"+cm.Name)
				return true
			}
		}
		switch role {
		case roleGlobal:
			// Global limits are platform-owned: only honored from the controller's
			// own namespace so a tenant can't throttle other tenants' traffic.
			if cm.Namespace != ctrl.PodNamespace {
				slog.Warn("ratelimit: ignoring global limits outside controller namespace",
					"configmap", cm.Namespace+"/"+cm.Name, "pod_namespace", ctrl.PodNamespace)
				return true
			}
			globalCMs = append(globalCMs, cm)
		case roleZone:
			key := cm.Namespace + "/" + cm.Name
			zoneDocs[key] = append(zoneDocs[key], sortedDataValues(cm.Data)...)
		}
		return true
	})

	// Deterministic namespace/name order for multiple global ConfigMaps — the
	// sync.Map.Range above visits them in random order, and both limit evaluation
	// order and the fingerprint depend on concatenation order.
	sort.Slice(globalCMs, func(i, j int) bool {
		if globalCMs[i].Namespace != globalCMs[j].Namespace {
			return globalCMs[i].Namespace < globalCMs[j].Namespace
		}
		return globalCMs[i].Name < globalCMs[j].Name
	})
	var globalDocs []string
	for _, cm := range globalCMs {
		globalDocs = append(globalDocs, sortedDataValues(cm.Data)...)
	}

	// global: reapply only when the input changed. Skipping on a fingerprint
	// match leaves the live strategies — and their counters — untouched.
	globalFP := fingerprintDocs(globalDocs)
	if globalFP != ctrl.globalRLFingerprint {
		if limits, err := ratelimitrule.Parse(globalDocs...); err != nil {
			slog.Error("ratelimit: invalid global limits, keeping previous", "error", err)
		} else if err := ctrl.globalRateLimit.SetLimits(limits); err != nil {
			slog.Error("ratelimit: global limits rejected, keeping previous", "error", err)
		} else {
			// Only advance the fingerprint once the new input applied cleanly, so a
			// rejected edit is retried (not skipped) on the next reload.
			ctrl.globalRLFingerprint = globalFP
		}
	}

	// zones: reuse the existing Limiter per zone. An unchanged zone keeps its
	// instance with no SetLimits (fingerprint match) — counters intact; a changed
	// zone gets SetLimits on the same instance, all-or-nothing, with per-limit
	// counter carry-over. Zones absent from zoneDocs are dropped, new zones get a
	// fresh instance.
	cur := ctrl.rlZones.Load()
	newZones := make(map[string]*ratelimitrule.Limiter, len(zoneDocs))
	newFingerprints := make(map[string]string, len(zoneDocs))
	for key, docs := range zoneDocs {
		fp := fingerprintDocs(docs)
		var l *ratelimitrule.Limiter
		reused := false
		if cur != nil {
			if existing, ok := (*cur)[key]; ok {
				l = existing
				reused = true
			}
		}
		if reused && fp == ctrl.rlZoneFingerprints[key] {
			newZones[key] = l
			newFingerprints[key] = fp
			continue
		}
		if !reused {
			l = &ratelimitrule.Limiter{
				NamePrefix: "zone:" + key,
				Observe:    observe.RateLimit,
				// Zone traffic usually carries a served Host, but an ingress with
				// host-less (catch-all) rules routes ANY Host into its zone — so
				// zones need the unknown-Host collapse as much as the global set.
				KnownHost: ctrl.IsKnownHost,
			}
		}
		if limits, err := ratelimitrule.Parse(docs...); err != nil {
			slog.Error("ratelimit: invalid zone limits, keeping previous", "zone", key, "error", err)
			// keep the prior fingerprint (if any) so the bad input is retried.
			newFingerprints[key] = ctrl.rlZoneFingerprints[key]
		} else if err := l.SetLimits(limits); err != nil {
			slog.Error("ratelimit: zone limits rejected, keeping previous", "zone", key, "error", err)
			newFingerprints[key] = ctrl.rlZoneFingerprints[key]
		} else {
			newFingerprints[key] = fp
		}
		newZones[key] = l
	}
	ctrl.rlZones.Store(&newZones)
	ctrl.rlZoneFingerprints = newFingerprints
	slog.Info("reloaded ratelimit", "global_limits", len(ctrl.globalRateLimit.IDs()), "zones", len(newZones))
}
