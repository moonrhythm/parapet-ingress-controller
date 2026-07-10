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

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/metric"
	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
	"github.com/moonrhythm/parapet-ingress-controller/wafclaim"
	"github.com/moonrhythm/parapet-ingress-controller/wafevent"
	"github.com/moonrhythm/parapet-ingress-controller/wafrule"
)

// wafLabelKey marks a ConfigMap as WAF input. Its value selects the role:
// "global" (baseline ruleset, honored only in the controller's own namespace)
// or "zone" (a tenant zone whose ID is the ConfigMap name). A single key means
// one watch with one existence selector catches both roles. The role values
// are shared with the rate-limit ConfigMaps (controller_ratelimit.go), which
// follow the same global/zone model under their own label key.
const (
	wafLabelKey = "parapet.moonrhythm.io/waf"
	roleGlobal  = "global"
	roleZone    = "zone"
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
	// SkipValidated reports requests whose WAF validation already happened at a
	// trusted upstream hop (the edge proxy runs the same global+zone rules) —
	// the global and zone WAF skip evaluation for them. Built from
	// WAF_VALIDATED_PROXY in main; nil (the default) evaluates every request
	// here. Must be set before GlobalWAF() is mounted.
	SkipValidated func(*http.Request) bool
	// Events, when non-nil, receives sampled zone-scope match events (the
	// per-pod ring served to the collector on WAF_EVENTS_LISTEN — see
	// SPEC-waf-events). nil disables capture entirely; global-scope matches are
	// never captured (the platform baseline is ours to debug, not tenant data).
	// Set from WAF_EVENTS_* in main, before InitWAF().
	Events *wafevent.Buffer
}

// InitWAF builds the global WAF instance and the (empty) zone registry. Call
// after setting WAFConfig and PodNamespace, before Watch(). No-op when disabled.
func (ctrl *Controller) InitWAF() {
	if !ctrl.WAFConfig.Enabled {
		return
	}
	ctrl.globalWAF = ctrl.newWAF(roleGlobal)
	empty := map[string]*waf.WAF{}
	ctrl.zones.Store(&empty)
	ctrl.zoneFingerprints = map[string]string{}
}

// GlobalWAF returns the global WAF middleware to mount in the server chain, or
// nil when the WAF is disabled. An enabled WAF with no rules loaded is a cheap
// pass-through. When WAFConfig.SkipValidated is set, requests it matches bypass
// the ruleset entirely (their WAF verdict was already decided at the edge).
func (ctrl *Controller) GlobalWAF() parapet.Middleware {
	if ctrl.globalWAF == nil {
		return nil
	}
	skip := ctrl.WAFConfig.SkipValidated
	if skip == nil {
		return ctrl.globalWAF
	}
	return parapet.MiddlewareFunc(func(h http.Handler) http.Handler {
		wafH := ctrl.globalWAF.ServeHandler(h)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skip(r) {
				metric.WAFSkip(roleGlobal)
				h.ServeHTTP(w, r)
				return
			}
			// Not validated: drop any claim header so it can't reach the CEL
			// rules below (request.headers) or the zone-WAF skip downstream. A
			// validated request keeps it in-chain — the zone skip re-checks it —
			// but it never reaches the backend either way: the proxy deletes it
			// at the upstream boundary (proxy.New's Director).
			r.Header.Del(wafclaim.Header)
			wafH.ServeHTTP(w, r)
		})
	})
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
	return ctrl.newScopedWAF(scope, "")
}

// newZoneWAF builds the WAF instance for one zone registry key
// (<namespace>/<name>). newWAF is per-scope, not per-zone, so the zone
// identity must be closed over at instance construction for sampled match
// events to carry it — one waf.WAF belongs to exactly one registry key.
func (ctrl *Controller) newZoneWAF(key string) *waf.WAF {
	return ctrl.newScopedWAF(roleZone, key)
}

func (ctrl *Controller) newScopedWAF(scope, zoneKey string) *waf.WAF {
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
	// Eval latency + outcome, once per evaluated request — the pass path OnMatch
	// can't see. Handles resolve here (per WAF instance), not per request.
	w.Observe = observe.WAFEval(scope)
	// The event ring only samples zone-scope matches (tenant data); resolved
	// once at instance construction so the hook below stays branch-cheap.
	events := ctrl.WAFConfig.Events
	if zoneKey == "" {
		events = nil
	}
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
		if events != nil {
			r := ev.Request
			// The enrich callback runs only for events admitted past the
			// sampling caps, so a cap-rejected flood never pays the GeoIP
			// lookups. MatchEvent doesn't carry country/ASN, so they're
			// re-resolved here (memory lookups, memoized per client IP).
			events.Append(wafevent.Event{
				Zone:     zoneKey,
				RuleID:   ev.RuleID,
				Action:   ev.Action.String(),
				Status:   ev.Status,
				ClientIP: ev.ClientIP,
				Method:   r.Method,
				Host:     r.Host,
				Path:     r.URL.Path,
			}, func(out *wafevent.Event) {
				if f := ctrl.WAFConfig.Country; f != nil {
					// The WAF resolver's "XX" sentinel means "DB loaded, IP
					// unresolved"; the event wire format wants "" for that.
					if cc := f(r); cc != "XX" {
						out.Country = cc
					}
				}
				if f := ctrl.WAFConfig.ASN; f != nil {
					out.ASN = f(r)
				}
			})
		}
	}
	return w
}

func (ctrl *Controller) watchConfigMaps(ctx context.Context) {
	watchFn := func(ctx context.Context, namespace string) (watch.Interface, error) {
		return k8s.WatchConfigMaps(ctx, namespace, wafLabelKey)
	}
	listFn := func(ctx context.Context, namespace string) ([]v1.ConfigMap, error) {
		return k8s.GetConfigMaps(ctx, namespace, wafLabelKey)
	}
	watchResource(ctx, ctrl.watchNamespace, "configmaps", watchFn, listFn,
		&ctrl.watchedConfigMaps,
		func(_ *v1.ConfigMap) { ctrl.reloadWAF() },
		func(_ *v1.ConfigMap) { ctrl.reloadWAF() },
		ctrl.reloadWAF,
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
	// Serialize the whole pass: the debounce can fire two reloadWAFDebounced
	// goroutines concurrently (see wafReloadMu), and the fingerprint string + map
	// below are a read-modify-write that must be atomic across the pass.
	ctrl.wafReloadMu.Lock()
	defer ctrl.wafReloadMu.Unlock()

	defer func() {
		if err := recover(); err != nil {
			slog.Error("reload waf failed", "error", err)
		}
	}()

	var globalCMs []*v1.ConfigMap
	zoneDocs := map[string][]string{}

	ctrl.watchedConfigMaps.Range(func(_, value any) bool {
		cm := value.(*v1.ConfigMap)
		role := cm.Labels[wafLabelKey]
		// Refuse a ConfigMap labeled for more than one feature (one ConfigMap per
		// feature, by policy): both reloaders would consume all its data values,
		// and the lenient YAML parsers cross-parse the other feature's documents to
		// zero entries — a multi-labeled ConfigMap would quietly feed each side an
		// empty/garbage set. Gated on a recognized WAF role because the fs backend
		// ignores label selectors, so this store also holds other features'
		// ConfigMaps there — those must fall through silently, not warn.
		if role == roleGlobal || role == roleZone {
			if other, ok := carriesOtherFeatureLabel(cm, wafLabelKey); ok {
				slog.Warn("waf: ignoring configmap that also carries another feature label; use one configmap per feature",
					"configmap", cm.Namespace+"/"+cm.Name, "other_label", other)
				return true
			}
		}
		switch role {
		case roleGlobal:
			// Global rules are platform-owned: only honored from the controller's
			// own namespace so a tenant can't inject baseline rules.
			if cm.Namespace != ctrl.PodNamespace {
				slog.Warn("waf: ignoring global ruleset outside controller namespace",
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

	// Concatenate global ConfigMaps in a deterministic namespace/name order. The
	// sync.Map.Range above visits them in random order, so without this the
	// concatenation order of multiple global ConfigMaps — and thus equal-priority
	// rule precedence and the fingerprint below — would flip between reloads.
	// (Zones don't need this: a zone key is one ConfigMap's namespace/name, so its
	// docs come from a single ConfigMap.)
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
			w = ctrl.newZoneWAF(key)
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
	slog.Info("reloaded waf", "global_rules", len(ctrl.globalWAF.Rules()), "zones", len(newZones))
}

// fingerprintDocs returns a content fingerprint of the config documents that
// feed a single compiled instance (a WAF ruleset or a rate-limit set). Callers
// pass the already-sorted, deterministic doc slice (sortedDataValues), so equal
// effective input yields an equal fingerprint regardless of ConfigMap map
// iteration order. The length prefix per doc keeps concatenation unambiguous
// (so ["a","bc"] and ["ab","c"] differ).
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

// sortedDataValues returns the ConfigMap data values ordered by key, so
// document declaration order (which matters for equal-priority WAF rules and
// for rate-limit evaluation order) is deterministic across reloads regardless
// of map iteration order.
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
