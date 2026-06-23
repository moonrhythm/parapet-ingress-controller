package edgecp

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Coraza ConfigMap markers — mirror the controller's (controller_coraza.go).
const (
	CorazaLabelKey   = "parapet.moonrhythm.io/coraza"
	corazaRoleGlobal = "global"
	corazaRoleZone   = "zone"
	// CorazaZoneAnnotation binds an Ingress to a Coraza zone (bare id or "ns/id").
	CorazaZoneAnnotation = "parapet.moonrhythm.io/coraza-zone"
)

// CorazaStore holds everything the edge needs to run the Coraza (SecLang/CRS)
// firewall: the global baseline (same for every edge), the tenant zone rulesets
// (keyed "<ns>/<name>"), and the path-aware zone bindings (route pattern →
// zoneKey, the controller's own route keys). Unlike WafStore there is no legacy
// host→zone map — Coraza is a new feature with no old edges to support — so only
// the path-aware routeZone binding is shipped. Lock-free reads via atomic
// pointers; the three inputs (global ConfigMaps, zone ConfigMaps, Ingresses)
// update independently and `scoped()` filters per edge.
type CorazaStore struct {
	mu        sync.RWMutex // write-held by Set*/recompute; read-held by scoped for a consistent snapshot
	global    atomic.Pointer[string]
	zones     atomic.Pointer[map[string]string] // zoneKey -> SecLang directives
	routeZone atomic.Pointer[map[string]string] // route pattern ("host/path[/]") -> zoneKey
	gen       atomic.Uint64
	curEtag   atomic.Pointer[string]
}

func NewCorazaStore() *CorazaStore {
	s := &CorazaStore{}
	empty := ""
	z := map[string]string{}
	rz := map[string]string{}
	s.global.Store(&empty)
	s.zones.Store(&z)
	s.routeZone.Store(&rz)
	et := etagOfString("")
	s.curEtag.Store(&et)
	return s
}

// SetGlobal replaces the global baseline ruleset (concatenated SecLang).
func (s *CorazaStore) SetGlobal(rules string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.global.Store(&rules)
	s.recompute()
}

// SetZones replaces the full zone registry (zoneKey -> SecLang directives).
func (s *CorazaStore) SetZones(zones map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zones.Store(&zones)
	s.recompute()
}

// SetIngressDerived replaces the path-aware zone binding (route pattern ->
// zoneKey).
func (s *CorazaStore) SetIngressDerived(rz map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routeZone.Store(&rz)
	s.recompute()
}

// recompute bumps the generation + etag when the combined content changes.
// Caller holds s.mu.
func (s *CorazaStore) recompute() {
	et := etagOfString(s.fingerprint())
	if prev := s.curEtag.Load(); prev != nil && *prev == et {
		return
	}
	s.gen.Add(1)
	s.curEtag.Store(&et)
}

func (s *CorazaStore) fingerprint() string {
	var b strings.Builder
	b.WriteString(*s.global.Load())
	b.WriteByte(0)
	writeSortedMap(&b, *s.zones.Load())
	b.WriteByte(0)
	writeSortedMap(&b, *s.routeZone.Load())
	return b.String()
}

// Version is the store's full-content etag — an opaque change signal for the
// /v1/events stream (per-edge scoping happens at fetch time, not here).
func (s *CorazaStore) Version() string { return *s.curEtag.Load() }

// corazaScopedSnapshot is the per-edge Coraza payload: global (shared) + only the
// zones and route bindings for hosts the edge is allowed to serve.
type corazaScopedSnapshot struct {
	generation uint64
	global     string
	zones      map[string]string
	routeZone  map[string]string
}

// scoped builds the response for an edge, including only route→zone entries whose
// host the edge may serve (per `allow`) and the zones those entries reference.
// Global is always included. Reads under the read lock so global/zones/routeZone/
// gen are a single consistent snapshot (mirrors WafStore.scoped).
func (s *CorazaStore) scoped(allow func(host string) bool) corazaScopedSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	allZones := *s.zones.Load()
	allRouteZone := *s.routeZone.Load()

	zones := map[string]string{}
	routeZone := map[string]string{}
	for pattern, zoneKey := range allRouteZone {
		if !allow(patternHost(pattern)) {
			continue
		}
		routeZone[pattern] = zoneKey
		if rules, ok := allZones[zoneKey]; ok {
			zones[zoneKey] = rules
		}
	}
	return corazaScopedSnapshot{
		generation: s.gen.Load(),
		global:     *s.global.Load(),
		zones:      zones,
		routeZone:  routeZone,
	}
}

// concatGlobalCorazaRules collects the global ruleset from the given ConfigMaps:
// only those labeled `…/coraza: global` AND living in podNamespace (the
// platform-owned baseline boundary). Directives are joined with newlines (plain
// SecLang, not the "\n---\n" YAML-doc separator the CEL WAF uses).
//
// The matching ConfigMaps are sorted by namespace/name before concatenation,
// matching the controller (controller_coraza.go) — k8s.GetConfigMaps order is
// not stable across CP replicas, and an unstable concatenation would change the
// per-edge ETag between replicas (defeating 304 revalidation) and, worse for
// SecLang, the rule execution order across multiple global ConfigMaps.
func concatGlobalCorazaRules(cms []wafConfigMap, podNamespace string) string {
	var globals []wafConfigMap
	for _, cm := range cms {
		if cm.labels[CorazaLabelKey] == corazaRoleGlobal && cm.namespace == podNamespace {
			globals = append(globals, cm)
		}
	}
	sortConfigMapsByName(globals)
	var docs []string
	for _, cm := range globals {
		docs = append(docs, sortedValues(cm.data)...)
	}
	return strings.Join(docs, "\n")
}

// sortConfigMapsByName orders ConfigMaps by (namespace, name) so a concatenation
// over them is deterministic regardless of the k8s list order — shared by the
// global-ruleset concat helpers.
func sortConfigMapsByName(cms []wafConfigMap) {
	sort.Slice(cms, func(i, j int) bool {
		if cms[i].namespace != cms[j].namespace {
			return cms[i].namespace < cms[j].namespace
		}
		return cms[i].name < cms[j].name
	})
}

// collectCorazaZoneRules collects zone ConfigMaps (any namespace) into
// zoneKey ("<ns>/<name>") -> concatenated SecLang directives.
func collectCorazaZoneRules(cms []wafConfigMap) map[string]string {
	out := map[string]string{}
	for _, cm := range cms {
		if cm.labels[CorazaLabelKey] != corazaRoleZone {
			continue
		}
		key := cm.namespace + "/" + cm.name
		docs := sortedValues(cm.data)
		if existing := out[key]; existing != "" {
			docs = append([]string{existing}, docs...)
		}
		out[key] = strings.Join(docs, "\n")
	}
	return out
}
