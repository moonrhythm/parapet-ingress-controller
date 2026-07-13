package controller

import (
	"context"
	"log/slog"
	"net/http"
	"sort"

	"github.com/moonrhythm/parapet"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/transformrule"
)

// transformLabelKey marks a ConfigMap as transform input. Its value selects the
// role, following the WAF/ratelimit model: "global" (baseline mutations applied
// to all traffic, honored only in the controller's own namespace) or "zone" (a
// per-(project, location) zone whose id is the ConfigMap name). It is a separate
// label key (and a separate watch) because a Kubernetes label selector can't OR
// two keys; the store stays separate too.
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

// Options returns the compile options shared by every transform surface
// (global, zone, and the inline-annotation plugin), so all three are bounded
// and geo-resolved identically.
func (c TransformConfig) Options() transformrule.Options {
	return transformrule.Options{
		Country:             c.Country,
		ASN:                 c.ASN,
		FilterCostLimit:     c.FilterCostLimit,
		FilterDisableMacros: c.FilterDisableMacros,
	}
}

func (ctrl *Controller) transformOptions() transformrule.Options {
	return ctrl.TransformConfig.Options()
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

// GlobalTransform returns the global transform middleware to mount in the
// server chain, or nil when the feature is disabled. The compiled set is looked
// up live per request (a transformrule.Zone is immutable, so reloads swap the
// pointer), so global edits propagate without a mux rebuild; no set loaded
// (nil) passes traffic through unmodified — a safe no-op.
func (ctrl *Controller) GlobalTransform() parapet.Middleware {
	if !ctrl.TransformConfig.Enabled {
		return nil
	}
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if z := ctrl.globalTransform.Load(); z != nil {
				z.ServeHandler(h).ServeHTTP(w, r)
				return
			}
			h.ServeHTTP(w, r)
		})
	})
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

// reloadTransformDebounced rebuilds the global set and the zone registry from
// the watched ConfigMaps. Like the WAF/ratelimit reloads it never touches
// ctrl.mux — a transform edit is a Parse + pointer/registry swap. Parse is
// all-or-nothing, so a bad set keeps its last-good compiled one; unchanged
// inputs (fingerprint match) are skipped entirely (the compiled Zone is reused).
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

	var globalCMs []*v1.ConfigMap
	zoneDocs := map[string][]string{}

	ctrl.watchedTransformConfigMaps.Range(func(_, value any) bool {
		cm := value.(*v1.ConfigMap)
		role := cm.Labels[transformLabelKey]
		// Only a "global"- or "zone"-roled ConfigMap is transform input; anything
		// else in this store (the fs backend ignores label selectors) falls through
		// silently.
		if role != roleGlobal && role != roleZone {
			return true
		}
		// Refuse a ConfigMap labeled for more than one feature (one ConfigMap per
		// feature, by deployer policy): every reloader consumes all data values, so
		// a multi-labeled ConfigMap would feed each side the other's documents,
		// which the lenient YAML parsers cross-parse to empty/garbage sets. The
		// role check above already gated on a recognized transform role (the fs
		// backend rationale).
		if other, ok := carriesOtherFeatureLabel(cm, transformLabelKey); ok {
			slog.Warn("transform: ignoring configmap that also carries another feature label; use one configmap per feature",
				"configmap", cm.Namespace+"/"+cm.Name, "other_label", other)
			return true
		}
		if role == roleGlobal {
			// Global transforms are platform-owned: only honored from the
			// controller's own namespace so a tenant can't mutate all traffic.
			if cm.Namespace != ctrl.PodNamespace {
				slog.Warn("transform: ignoring global set outside controller namespace",
					"configmap", cm.Namespace+"/"+cm.Name, "pod_namespace", ctrl.PodNamespace)
				return true
			}
			globalCMs = append(globalCMs, cm)
			return true
		}
		key := cm.Namespace + "/" + cm.Name
		zoneDocs[key] = append(zoneDocs[key], sortedDataValues(cm.Data)...)
		return true
	})

	opts := ctrl.transformOptions()

	// Concatenate global ConfigMaps in a deterministic name order (they all live
	// in PodNamespace; the sync.Map.Range above visits them in random order) so
	// equal-priority rule precedence and the fingerprint are stable across
	// reloads — same reasoning as the WAF's global concatenation.
	sort.Slice(globalCMs, func(i, j int) bool { return globalCMs[i].Name < globalCMs[j].Name })
	var globalDocs []string
	for _, cm := range globalCMs {
		globalDocs = append(globalDocs, sortedDataValues(cm.Data)...)
	}
	globalFP := fingerprintDocs(globalDocs)
	if globalFP != ctrl.globalTransformFingerprint {
		if len(globalDocs) == 0 {
			// No global ConfigMap: drop to nil so the mounted middleware is a pure
			// pass-through (cheaper than an empty compiled Zone).
			ctrl.globalTransform.Store(nil)
			ctrl.globalTransformFingerprint = globalFP
		} else if zone, err := transformrule.Parse(opts, globalDocs...); err != nil {
			// All-or-nothing: keep the last-good global set live and keep its prior
			// fingerprint so the bad input is retried next reload.
			slog.Error("transform: invalid global set, keeping previous", "error", err)
		} else {
			ctrl.globalTransform.Store(zone)
			ctrl.globalTransformFingerprint = globalFP
		}
	}

	cur := ctrl.transformZones.Load()
	newZones := make(map[string]*transformrule.Zone, len(zoneDocs))
	newFingerprints := make(map[string]string, len(zoneDocs))

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
	globalRules := 0
	if z := ctrl.globalTransform.Load(); z != nil {
		globalRules = len(z.IDs())
	}
	slog.Info("reloaded transform", "global_rules", globalRules, "zones", len(newZones))
}
