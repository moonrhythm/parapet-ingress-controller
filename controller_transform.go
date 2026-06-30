package controller

import (
	"context"
	"log/slog"
	"net/http"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/transformrule"
)

// transformLabelKey marks a ConfigMap as transform input. Unlike the WAF and
// rate-limit labels there is no "global" baseline — transforms are a per-(project,
// location) zone only — so the value is always "zone" (roleZone) and its id is the
// ConfigMap name. It is a separate label key (and a separate watch) because a
// Kubernetes label selector can't OR two keys; the store stays separate too.
const transformLabelKey = "parapet.moonrhythm.io/transform"

// TransformConfig configures the ConfigMap-driven transform layer. It is set on
// the Controller before Watch(). When Enabled is false the feature does no work:
// no ConfigMap watch, no mount, no per-request cost.
type TransformConfig struct {
	Enabled bool
	// Country / ASN resolve the client's GeoIP country / ASN for a filter that
	// references request.country / request.asn — the same resolvers the WAF and
	// ratelimit use. nil makes those references simply never match (not an error),
	// matching ratelimit's geo-without-DB behavior. Set from WAF_GEOIP_DB /
	// WAF_ASN_DB in main.
	Country func(*http.Request) string
	ASN     func(*http.Request) int64
	// FilterCostLimit / FilterDisableMacros bound a rule's CEL `filter` exactly
	// like a WAF rule. Set from WAF_COST_LIMIT / WAF_DISABLE_MACROS in main so a
	// transform filter — same CEL engine, same tenant-authored trust surface — is
	// hardened by the same operator knobs. Zero values leave the parapet defaults.
	FilterCostLimit     uint64
	FilterDisableMacros bool
}

func (ctrl *Controller) transformOptions() transformrule.Options {
	return transformrule.Options{
		Country:             ctrl.TransformConfig.Country,
		ASN:                 ctrl.TransformConfig.ASN,
		FilterCostLimit:     ctrl.TransformConfig.FilterCostLimit,
		FilterDisableMacros: ctrl.TransformConfig.FilterDisableMacros,
	}
}

// InitTransform seeds the (empty) zone registry. Call after setting
// TransformConfig, before Watch(). No-op when disabled — disabled means no
// ConfigMap watch, no mount, no per-request work.
func (ctrl *Controller) InitTransform() {
	if !ctrl.TransformConfig.Enabled {
		return
	}
	empty := map[string]*transformrule.Zone{}
	ctrl.transformZones.Store(&empty)
	ctrl.transformZoneFingerprints = map[string]string{}
}

// LookupTransformZone returns the compiled transform zone for a registry key
// (<namespace>/<name>), or nil if no such zone is loaded. Looked up live on the
// request path so zone edits and new zones propagate without a mux rebuild.
func (ctrl *Controller) LookupTransformZone(key string) *transformrule.Zone {
	m := ctrl.transformZones.Load()
	if m == nil {
		return nil
	}
	return (*m)[key]
}

func (ctrl *Controller) watchTransformConfigMaps(ctx context.Context) {
	watchFn := func(ctx context.Context, namespace string) (watch.Interface, error) {
		return k8s.WatchConfigMaps(ctx, namespace, transformLabelKey)
	}
	listFn := func(ctx context.Context, namespace string) ([]v1.ConfigMap, error) {
		return k8s.GetConfigMaps(ctx, namespace, transformLabelKey)
	}
	// Named "transform-configmaps" so its watch/resync log lines are
	// distinguishable from the WAF's and ratelimit's loops.
	watchResource(ctx, ctrl.watchNamespace, "transform-configmaps", watchFn, listFn,
		&ctrl.watchedTransformConfigMaps,
		func(_ *v1.ConfigMap) { ctrl.reloadTransform() },
		func(_ *v1.ConfigMap) { ctrl.reloadTransform() },
		ctrl.reloadTransform,
	)
}

func (ctrl *Controller) reloadTransform() {
	ctrl.reloadTransformDebounce.Call()
}

// reloadTransformDebounced rebuilds the zone registry from the watched
// ConfigMaps. Like the WAF/ratelimit reloads it never touches ctrl.mux — a
// transform edit is a Parse + registry swap. Parse is all-or-nothing, so a bad
// zone keeps its last-good compiled set; unchanged inputs (fingerprint match)
// are skipped entirely (the compiled Zone is reused).
func (ctrl *Controller) reloadTransformDebounced() {
	if !ctrl.TransformConfig.Enabled {
		return
	}
	// Serialize the whole pass: the debounce can fire two passes concurrently
	// (same hazard as wafReloadMu/rlReloadMu), and the fingerprint map below is a
	// read-modify-write that must be atomic across the pass.
	ctrl.transformReloadMu.Lock()
	defer ctrl.transformReloadMu.Unlock()

	defer func() {
		if err := recover(); err != nil {
			slog.Error("reload transform failed", "error", err)
		}
	}()

	zoneDocs := map[string][]string{}

	ctrl.watchedTransformConfigMaps.Range(func(_, value any) bool {
		cm := value.(*v1.ConfigMap)
		// Only a "zone"-roled ConfigMap is transform input; anything else in this
		// store (the fs backend ignores label selectors) falls through silently.
		if cm.Labels[transformLabelKey] != roleZone {
			return true
		}
		// Refuse a ConfigMap labeled for more than one feature (one ConfigMap per
		// feature, by deployer policy): every reloader consumes all data values, so
		// a multi-labeled ConfigMap would feed each side the other's documents,
		// which the lenient YAML parsers cross-parse to empty/garbage sets silently.
		if _, ok := cm.Labels[wafLabelKey]; ok {
			slog.Warn("transform: ignoring configmap that also carries the waf label; use one configmap per feature",
				"configmap", cm.Namespace+"/"+cm.Name)
			return true
		}
		if _, ok := cm.Labels[rateLimitLabelKey]; ok {
			slog.Warn("transform: ignoring configmap that also carries the ratelimit label; use one configmap per feature",
				"configmap", cm.Namespace+"/"+cm.Name)
			return true
		}
		key := cm.Namespace + "/" + cm.Name
		zoneDocs[key] = append(zoneDocs[key], sortedDataValues(cm.Data)...)
		return true
	})

	cur := ctrl.transformZones.Load()
	newZones := make(map[string]*transformrule.Zone, len(zoneDocs))
	newFingerprints := make(map[string]string, len(zoneDocs))
	opts := ctrl.transformOptions()

	for key, docs := range zoneDocs {
		fp := fingerprintDocs(docs)

		// Unchanged input: reuse the existing compiled Zone untouched.
		if cur != nil {
			if existing, ok := (*cur)[key]; ok && fp == ctrl.transformZoneFingerprints[key] {
				newZones[key] = existing
				newFingerprints[key] = fp
				continue
			}
		}

		zone, err := transformrule.Parse(opts, docs...)
		if err != nil {
			slog.Error("transform: invalid zone, keeping previous", "zone", key, "error", err)
			// All-or-nothing: keep the last-good compiled Zone live (if any) and
			// keep its prior fingerprint so the bad input is retried next reload. A
			// zone with no previous good set is simply dropped (the plugin then
			// passes traffic through unmodified — a safe no-op).
			if cur != nil {
				if existing, ok := (*cur)[key]; ok {
					newZones[key] = existing
					newFingerprints[key] = ctrl.transformZoneFingerprints[key]
				}
			}
			continue
		}
		newZones[key] = zone
		newFingerprints[key] = fp
	}

	ctrl.transformZones.Store(&newZones)
	ctrl.transformZoneFingerprints = newFingerprints
	slog.Info("reloaded transform", "zones", len(newZones))
}
