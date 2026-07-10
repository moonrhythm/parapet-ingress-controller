package controller

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"

	"github.com/moonrhythm/parapet"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/corazawaf"
	"github.com/moonrhythm/parapet-ingress-controller/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/metric"
	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
)

// corazaLabelKey marks a ConfigMap as Coraza (OWASP CRS / SecLang) input,
// mirroring the WAF's wafLabelKey and the rate limiter's rateLimitLabelKey: value
// "global" is the baseline ruleset (honored only in the controller's own
// namespace), value "zone" is a tenant zone whose ID is the ConfigMap name. It is
// a separate label key — and a separate watch and store — because a label
// selector can't OR two keys, and the SecLang ruleset is a different rule
// language than the CEL WAF's. The Coraza layer is independent of the CEL WAF:
// either can be enabled without the other, and "global off, one zone on" is just
// "no global ConfigMap, one zone ConfigMap bound by annotation".
const corazaLabelKey = "parapet.moonrhythm.io/coraza"

// CorazaConfig configures the Coraza (SecLang/CRS) firewall. It is set on the
// Controller before Watch(). When Enabled is false the feature does no work: no
// ConfigMap watch, no mount, no per-request cost.
type CorazaConfig struct {
	Enabled bool
	// RootFS resolves Include directives — wire the embedded OWASP CRS here so a
	// ruleset can `Include @crs-setup.conf.example` + `Include @owasp_crs/*.conf`
	// (the bare `@crs-setup` / `@owasp_crs` forms do not resolve — Include globs
	// only on '*'). nil disables bundled-ruleset includes.
	RootFS fs.FS
	// RequestBodyLimit caps request-body inspection in bytes. <= 0 (the default)
	// inspects only the URI and headers — no body is buffered. Set from
	// CORAZA_REQUEST_BODY_LIMIT in main.
	RequestBodyLimit int
	// ClientIP resolves the true client IP (parapet XFF precedence) for Coraza's
	// connection/REMOTE_ADDR. Set to geoip.ClientIP in main; nil falls back to the
	// RemoteAddr host.
	ClientIP func(*http.Request) string
}

// InitCoraza builds the global Coraza instance and the (empty) zone registry.
// Call after setting CorazaConfig and PodNamespace, before Watch(). No-op when
// disabled.
func (ctrl *Controller) InitCoraza() {
	if !ctrl.CorazaConfig.Enabled {
		return
	}
	ctrl.globalCoraza = ctrl.newCoraza(roleGlobal, "")
	empty := map[string]*corazawaf.Instance{}
	ctrl.corazaZones.Store(&empty)
	ctrl.corazaZoneFingerprints = map[string]string{}
}

// GlobalCoraza returns the global Coraza middleware to mount in the server
// chain, or nil when disabled. An enabled instance with no rules loaded is a
// cheap pass-through (one atomic load). Unlike the CEL WAF there is no
// validated-proxy skip: the edge Coraza runs as defense-in-depth, so the core
// always evaluates its own Coraza ruleset.
func (ctrl *Controller) GlobalCoraza() parapet.Middleware {
	if ctrl.globalCoraza == nil {
		return nil
	}
	return ctrl.globalCoraza
}

// LookupCorazaZone returns the compiled Coraza instance for a zone registry key
// (<namespace>/<name>), or nil if no such zone is loaded. Looked up live on the
// request path so zone edits and new zones propagate without a mux rebuild.
func (ctrl *Controller) LookupCorazaZone(key string) *corazawaf.Instance {
	m := ctrl.corazaZones.Load()
	if m == nil {
		return nil
	}
	return (*m)[key]
}

// newCoraza builds a Coraza instance with the configured tunables and wires
// match events to metrics + logging. scope ("global"/"zone") and zone (the zone
// registry key <namespace>/<name>; "" for global) are the metric labels — zone
// is what makes a match attributable, since Coraza rule ids (CRS ids) are
// shared by every zone.
func (ctrl *Controller) newCoraza(scope, zone string) *corazawaf.Instance {
	return corazawaf.New(corazawaf.Options{
		RootFS:           ctrl.CorazaConfig.RootFS,
		RequestBodyLimit: ctrl.CorazaConfig.RequestBodyLimit,
		ClientIP:         ctrl.CorazaConfig.ClientIP,
		Observe:          observe.CorazaEval(scope),
		OnMatch: func(ev corazawaf.MatchEvent) {
			metric.CorazaMatch(ev.RuleID, ev.Severity, scope, zone)
			lvl := slog.LevelDebug
			if ev.Disruptive {
				lvl = slog.LevelInfo
			}
			slog.Log(context.Background(), lvl, "coraza match",
				"scope", scope, "zone", zone, "rule", ev.RuleID, "severity", ev.Severity,
				"disruptive", ev.Disruptive, "ip", ev.ClientIP, "uri", ev.URI,
				"message", ev.Message)
		},
	})
}

func (ctrl *Controller) watchCorazaConfigMaps(ctx context.Context) {
	watchFn := func(ctx context.Context, namespace string) (watch.Interface, error) {
		return k8s.WatchConfigMaps(ctx, namespace, corazaLabelKey)
	}
	listFn := func(ctx context.Context, namespace string) ([]v1.ConfigMap, error) {
		return k8s.GetConfigMaps(ctx, namespace, corazaLabelKey)
	}
	// Named "coraza-configmaps" so its watch/resync log lines are distinguishable
	// from the WAF's "configmaps" and the rate limiter's "ratelimit-configmaps".
	watchResource(ctx, ctrl.watchNamespace, "coraza-configmaps", watchFn, listFn,
		&ctrl.watchedCorazaConfigMaps,
		func(_ *v1.ConfigMap) { ctrl.reloadCoraza() },
		func(_ *v1.ConfigMap) { ctrl.reloadCoraza() },
		ctrl.reloadCoraza,
	)
}

func (ctrl *Controller) reloadCoraza() {
	ctrl.reloadCorazaDebounce.Call()
}

// reloadCorazaDebounced rebuilds the global ruleset and the zone registry from
// the watched ConfigMaps. Like the WAF reload it never touches ctrl.mux — a rule
// edit is a SetDirectives + registry swap. SetDirectives is all-or-nothing, so a
// bad ruleset keeps the last-good one; unchanged inputs (fingerprint match) are
// skipped entirely, leaving the live compiled instance untouched.
func (ctrl *Controller) reloadCorazaDebounced() {
	if !ctrl.CorazaConfig.Enabled || ctrl.globalCoraza == nil {
		return
	}
	// Serialize the whole pass: the debounce can fire two passes concurrently
	// (same hazard as wafReloadMu), and the fingerprint string + map below are a
	// read-modify-write that must be atomic across the pass.
	ctrl.corazaReloadMu.Lock()
	defer ctrl.corazaReloadMu.Unlock()

	defer func() {
		if err := recover(); err != nil {
			slog.Error("reload coraza failed", "error", err)
		}
	}()

	var globalCMs []*v1.ConfigMap
	zoneDocs := map[string][]string{}

	ctrl.watchedCorazaConfigMaps.Range(func(_, value any) bool {
		cm := value.(*v1.ConfigMap)
		switch cm.Labels[corazaLabelKey] {
		case roleGlobal:
			// Global rules are platform-owned: only honored from the controller's
			// own namespace so a tenant can't inject baseline rules.
			if cm.Namespace != ctrl.PodNamespace {
				slog.Warn("coraza: ignoring global ruleset outside controller namespace",
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
	// sync.Map.Range above visits them in random order, and both directive
	// concatenation order and the fingerprint depend on it.
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

	// global: recompile only when the rule input changed. An identical input
	// skips the SecLang compile and leaves the live ruleset untouched.
	globalFP := fingerprintDocs(globalDocs)
	if globalFP != ctrl.globalCorazaFingerprint {
		if err := ctrl.globalCoraza.SetDirectives(globalDocs...); err != nil {
			slog.Error("coraza: invalid global ruleset, keeping previous", "error", err)
		} else {
			// Advance the fingerprint only on a clean compile, so a rejected edit is
			// retried (not skipped) on the next reload.
			ctrl.globalCorazaFingerprint = globalFP
		}
	}

	// zones: reuse the existing instance per zone. An unchanged zone keeps its
	// compiled instance with no recompile (fingerprint match); a changed zone is
	// rebuilt via SetDirectives, all-or-nothing so a bad edit keeps last-good.
	// Zones absent from zoneDocs are dropped, new zones get a fresh instance.
	cur := ctrl.corazaZones.Load()
	newZones := make(map[string]*corazawaf.Instance, len(zoneDocs))
	newFingerprints := make(map[string]string, len(zoneDocs))
	for key, docs := range zoneDocs {
		fp := fingerprintDocs(docs)
		var c *corazawaf.Instance
		reused := false
		if cur != nil {
			if existing, ok := (*cur)[key]; ok {
				c = existing
				reused = true
			}
		}
		if reused && fp == ctrl.corazaZoneFingerprints[key] {
			newZones[key] = c
			newFingerprints[key] = fp
			continue
		}
		if !reused {
			c = ctrl.newCoraza(roleZone, key)
		}
		if err := c.SetDirectives(docs...); err != nil {
			slog.Error("coraza: invalid zone ruleset, keeping previous", "zone", key, "error", err)
			// keep the prior fingerprint (if any) so the bad input is retried.
			newFingerprints[key] = ctrl.corazaZoneFingerprints[key]
		} else {
			newFingerprints[key] = fp
		}
		newZones[key] = c
	}
	ctrl.corazaZones.Store(&newZones)
	ctrl.corazaZoneFingerprints = newFingerprints
	slog.Info("reloaded coraza", "global_loaded", ctrl.globalCoraza.Loaded(), "zones", len(newZones))
}
