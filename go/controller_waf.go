package controller

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/waf"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/go/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/go/metric"
	"github.com/moonrhythm/parapet-ingress-controller/go/wafrule"
)

// wafLabelKey marks a ConfigMap as WAF input. Its value selects the role:
// "global" (baseline ruleset, honored only in the controller's own namespace)
// or "zone" (a tenant zone whose ID is the ConfigMap name). A single key means
// one watch with one existence selector catches both roles.
const (
	wafLabelKey   = "parapet.moonrhythm.io/waf"
	wafRoleGlobal = "global"
	wafRoleZone   = "zone"
)

// WAFConfig configures the WAF. It is set on the Controller before Watch().
// When Enabled is false the WAF does no work: no ConfigMap watch, no mount.
type WAFConfig struct {
	Enabled       bool
	FailClosed    bool          // rule eval error -> 500 instead of fail-open
	EvalTimeout   time.Duration // per-request deadline for the whole ruleset
	CostLimit     uint64        // CEL cost cap per rule (0 = waf default)
	InspectBody   int64         // inspect up to N body bytes (0 = body empty)
	DisableMacros bool          // refuse all/exists/map/filter in rules
	// Country resolves the client's ISO country for request.country (GeoIP).
	// nil leaves request.country empty. Set from WAF_GEOIP_DB in main.
	Country func(*http.Request) string
	// ASN resolves the client's autonomous system number for request.asn.
	// nil leaves request.asn 0. Set from WAF_ASN_DB in main.
	ASN func(*http.Request) int64
}

// InitWAF builds the global WAF instance and the (empty) zone registry. Call
// after setting WAFConfig and PodNamespace, before Watch(). No-op when disabled.
func (ctrl *Controller) InitWAF() {
	if !ctrl.WAFConfig.Enabled {
		return
	}
	ctrl.globalWAF = ctrl.newWAF(wafRoleGlobal)
	empty := map[string]*waf.WAF{}
	ctrl.zones.Store(&empty)
	ctrl.zoneFingerprints = map[string]string{}
}

// GlobalWAF returns the global WAF middleware to mount in the server chain, or
// nil when the WAF is disabled. An enabled WAF with no rules loaded is a cheap
// pass-through.
func (ctrl *Controller) GlobalWAF() parapet.Middleware {
	if ctrl.globalWAF == nil {
		return nil
	}
	return ctrl.globalWAF
}

// LookupZone returns the compiled WAF for a zone registry key
// (<namespace>/<name>), or nil if no such zone is loaded. Looked up live on the
// request path so zone edits and new zones propagate without a mux rebuild.
func (ctrl *Controller) LookupZone(key string) *waf.WAF {
	m := ctrl.zones.Load()
	if m == nil {
		return nil
	}
	return (*m)[key]
}

// newWAF builds a WAF instance with the configured tunables and wires match
// events to metrics + logging. scope ("global"/"zone") is the metric label.
func (ctrl *Controller) newWAF(scope string) *waf.WAF {
	w := waf.New()
	if ctrl.WAFConfig.FailClosed {
		w.FailMode = waf.FailClosed
	}
	w.EvalTimeout = ctrl.WAFConfig.EvalTimeout
	w.CostLimit = ctrl.WAFConfig.CostLimit
	w.InspectBody = ctrl.WAFConfig.InspectBody
	w.DisableMacros = ctrl.WAFConfig.DisableMacros
	w.Country = ctrl.WAFConfig.Country // GeoIP request.country (nil = empty)
	w.ASN = ctrl.WAFConfig.ASN         // GeoIP request.asn (nil = 0)
	// Logger catches eval errors (the fail-open path) and the module's own match
	// lines; kept at debug so a flood of matches can't spam the log (the metric
	// below is the always-on signal).
	w.Logger = waf.LoggerFunc(func(format string, args ...any) {
		slog.Debug(fmt.Sprintf(format, args...))
	})
	w.OnMatch = func(ev waf.MatchEvent) {
		metric.WAFMatch(ev.RuleID, ev.Action.String(), scope)
		lvl := slog.LevelDebug
		if ev.Action == waf.ActionBlock {
			lvl = slog.LevelInfo
		}
		slog.Log(context.Background(), lvl, "waf match",
			"scope", scope, "rule", ev.RuleID, "action", ev.Action.String(),
			"status", ev.Status, "ip", ev.ClientIP, "method", ev.Request.Method,
			"host", ev.Request.Host, "path", ev.Request.URL.Path)
	}
	return w
}

func (ctrl *Controller) watchConfigMaps(ctx context.Context) {
	watchFn := func(ctx context.Context, namespace string) (watch.Interface, error) {
		return k8s.WatchConfigMaps(ctx, namespace, wafLabelKey)
	}
	watchResource(ctx, ctrl.watchNamespace, "configmaps", watchFn,
		&ctrl.watchedConfigMaps,
		func(_ *v1.ConfigMap) { ctrl.reloadWAF() },
		func(_ *v1.ConfigMap) { ctrl.reloadWAF() },
	)
}

func (ctrl *Controller) reloadWAF() {
	ctrl.reloadWAFDebounce.Call()
}

// reloadWAFDebounced rebuilds the global ruleset and the zone registry from the
// watched ConfigMaps. It never touches ctrl.mux: WAF rules are decoupled from
// routing, so a rule edit is just a SetRules + registry swap. Bad config is
// kept all-or-nothing by SetRules — the previous good ruleset stays live.
func (ctrl *Controller) reloadWAFDebounced() {
	if !ctrl.WAFConfig.Enabled || ctrl.globalWAF == nil {
		return
	}
	slog.Info("reload waf")

	defer func() {
		if err := recover(); err != nil {
			slog.Error("reload waf failed", "error", err)
		}
	}()

	var globalDocs []string
	zoneDocs := map[string][]string{}

	ctrl.watchedConfigMaps.Range(func(_, value any) bool {
		cm := value.(*v1.ConfigMap)
		switch cm.Labels[wafLabelKey] {
		case wafRoleGlobal:
			// Global rules are platform-owned: only honored from the controller's
			// own namespace so a tenant can't inject baseline rules.
			if cm.Namespace != ctrl.PodNamespace {
				slog.Warn("waf: ignoring global ruleset outside controller namespace",
					"configmap", cm.Namespace+"/"+cm.Name, "pod_namespace", ctrl.PodNamespace)
				return true
			}
			globalDocs = append(globalDocs, sortedDataValues(cm.Data)...)
		case wafRoleZone:
			key := cm.Namespace + "/" + cm.Name
			zoneDocs[key] = append(zoneDocs[key], sortedDataValues(cm.Data)...)
		}
		return true
	})

	// global: recompile only when the rule input changed. The fingerprint is over
	// the exact (sorted, deterministic) docs that feed SetRules, so an identical
	// input skips the CEL compile and leaves the live ruleset untouched.
	globalFP := fingerprintDocs(globalDocs)
	if globalFP != ctrl.globalWAFFingerprint {
		if rules, err := wafrule.Parse(globalDocs...); err != nil {
			slog.Error("waf: invalid global ruleset, keeping previous", "error", err)
		} else if err := ctrl.globalWAF.SetRules(rules); err != nil {
			slog.Error("waf: global ruleset rejected, keeping previous", "error", err)
		} else {
			// Only advance the fingerprint once the new input compiled cleanly, so a
			// rejected edit is retried (not skipped) on the next reload.
			ctrl.globalWAFFingerprint = globalFP
		}
	}

	// zones: reuse the existing *waf.WAF per zone. An unchanged zone keeps its
	// compiled instance with no recompile (fingerprint match); a changed zone is
	// rebuilt via SetRules on the same instance, which is all-or-nothing so a bad
	// edit keeps that zone's last-good ruleset. Zones absent from zoneDocs are
	// dropped, new zones get a fresh instance — the post-reload registry is
	// identical to a full rebuild.
	cur := ctrl.zones.Load()
	newZones := make(map[string]*waf.WAF, len(zoneDocs))
	newFingerprints := make(map[string]string, len(zoneDocs))
	for key, docs := range zoneDocs {
		fp := fingerprintDocs(docs)
		var w *waf.WAF
		reused := false
		if cur != nil {
			if existing, ok := (*cur)[key]; ok {
				w = existing
				reused = true
			}
		}
		// Skip the recompile only when we are reusing an instance whose loaded
		// input fingerprint matches; a new/changed zone compiles below.
		if reused && fp == ctrl.zoneFingerprints[key] {
			newZones[key] = w
			newFingerprints[key] = fp
			continue
		}
		if !reused {
			w = ctrl.newWAF(wafRoleZone)
		}
		if rules, err := wafrule.Parse(docs...); err != nil {
			slog.Error("waf: invalid zone ruleset, keeping previous", "zone", key, "error", err)
			// keep the prior fingerprint (if any) so the bad input is retried.
			newFingerprints[key] = ctrl.zoneFingerprints[key]
		} else if err := w.SetRules(rules); err != nil {
			slog.Error("waf: zone ruleset rejected, keeping previous", "zone", key, "error", err)
			newFingerprints[key] = ctrl.zoneFingerprints[key]
		} else {
			newFingerprints[key] = fp
		}
		newZones[key] = w
	}
	ctrl.zones.Store(&newZones)
	ctrl.zoneFingerprints = newFingerprints
}

// fingerprintDocs returns a content fingerprint of the rule documents that feed
// a single WAF. Callers pass the already-sorted, deterministic doc slice
// (sortedDataValues), so equal effective input yields an equal fingerprint
// regardless of ConfigMap map iteration order. The length prefix per doc keeps
// concatenation unambiguous (so ["a","bc"] and ["ab","c"] differ).
func fingerprintDocs(docs []string) string {
	h := sha256.New()
	var lenbuf [8]byte
	for _, d := range docs {
		binary.LittleEndian.PutUint64(lenbuf[:], uint64(len(d)))
		h.Write(lenbuf[:])
		h.Write([]byte(d))
	}
	return string(h.Sum(nil))
}

// sortedDataValues returns the ConfigMap data values ordered by key, so rule
// declaration order (which matters within equal priority) is deterministic
// across reloads regardless of map iteration order.
func sortedDataValues(data map[string]string) []string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, data[k])
	}
	return out
}
