package edgecp

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// WAF ConfigMap markers — mirror the controller's (go/controller_waf.go).
const (
	WAFLabelKey   = "parapet.moonrhythm.io/waf"
	wafRoleGlobal = "global"
	wafRoleZone   = "zone"
	// WAFZoneAnnotation binds an Ingress to a zone (bare id or "ns/id").
	WAFZoneAnnotation = "parapet.moonrhythm.io/waf-zone"
)

// WafStore holds everything the edge needs to run the WAF: the global baseline
// (same for every edge), the tenant zone rulesets (keyed "<ns>/<name>"), and the
// zone bindings derived from Ingresses — the path-aware routeZone map (route
// pattern → zoneKey, the controller's own route keys) plus the legacy host→
// zoneKey map older edges still consume. Responses are scoped per edge by the
// caller (only the edge's allowed hosts/zones), so this store keeps the full
// set and `scoped()` filters it. Lock-free reads via atomic pointers; the three
// inputs (global ConfigMaps, zone ConfigMaps, Ingresses) update independently.
type WafStore struct {
	mu        sync.RWMutex // write-held by Set*/recompute; read-held by scoped for a consistent snapshot
	global    atomic.Pointer[string]
	zones     atomic.Pointer[map[string]string] // zoneKey -> rules YAML
	hostZone  atomic.Pointer[map[string]string] // lowercased host -> zoneKey (legacy, pre-path-aware edges)
	routeZone atomic.Pointer[map[string]string] // route pattern ("host/path[/]") -> zoneKey
	gen       atomic.Uint64
	curEtag   atomic.Pointer[string] // etag over the full content, bumps on change
}

func NewWafStore() *WafStore {
	s := &WafStore{}
	empty := ""
	z := map[string]string{}
	h := map[string]string{}
	rz := map[string]string{}
	s.global.Store(&empty)
	s.zones.Store(&z)
	s.hostZone.Store(&h)
	s.routeZone.Store(&rz)
	et := etagOfString("")
	s.curEtag.Store(&et)
	return s
}

// SetGlobal replaces the global baseline ruleset (concatenated YAML).
func (s *WafStore) SetGlobal(rules string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.global.Store(&rules)
	s.recompute()
}

// SetZones replaces the full zone registry (zoneKey -> rules YAML).
func (s *WafStore) SetZones(zones map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zones.Store(&zones)
	s.recompute()
}

// SetIngressDerived replaces both Ingress-derived bindings — the legacy
// host→zoneKey map and the path-aware routeZone map — in one recompute, so a
// single Ingress reload can't be observed half-applied.
func (s *WafStore) SetIngressDerived(hz, rz map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostZone.Store(&hz)
	s.routeZone.Store(&rz)
	s.recompute()
}

// recompute bumps the generation + global etag when the combined content changes.
// Caller holds s.mu.
func (s *WafStore) recompute() {
	et := etagOfString(s.fingerprint())
	if prev := s.curEtag.Load(); prev != nil && *prev == et {
		return
	}
	s.gen.Add(1)
	s.curEtag.Store(&et)
}

// fingerprint is a stable serialization of the full content (for the generation
// bump). Per-token ETags are computed over the scoped payload in the handler.
func (s *WafStore) fingerprint() string {
	var b strings.Builder
	b.WriteString(*s.global.Load())
	b.WriteByte(0)
	writeSortedMap(&b, *s.zones.Load())
	b.WriteByte(0)
	writeSortedMap(&b, *s.hostZone.Load())
	b.WriteByte(0)
	writeSortedMap(&b, *s.routeZone.Load())
	return b.String()
}

// scopedSnapshot is the per-edge WAF payload: global (shared) + only the zones
// and host bindings for hosts the edge is allowed to serve.
type scopedSnapshot struct {
	generation uint64
	global     string
	zones      map[string]string
	hostZone   map[string]string
	routeZone  map[string]string
}

// scoped builds the response for an edge, including only host→zone entries whose
// host the edge may serve (per `allow`) and the zones those entries reference.
// Global is always included (it's the platform baseline, identical for all edges).
//
// It reads global/zones/hostZone/gen under the read lock so the four are a single
// CONSISTENT snapshot of the store's state — without it, the four independent atomic
// reads could straddle a concurrent SetZones/SetHostZone/recompute and return, e.g.,
// a host→zone binding whose zone rules aren't in the (older) zones map, or a
// generation that doesn't match the payload. (Cross-reloader eventual consistency
// between the zone and ingress watches is inherent and corrected on the next poll;
// parapet re-runs the WAF authoritatively regardless.) scoped runs per edge poll, so
// the brief RLock is negligible.
func (s *WafStore) scoped(allow func(host string) bool) scopedSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	allZones := *s.zones.Load()
	allHostZone := *s.hostZone.Load()
	allRouteZone := *s.routeZone.Load()

	hostZone := map[string]string{}
	zones := map[string]string{}
	for host, zoneKey := range allHostZone {
		if !allow(host) {
			continue
		}
		hostZone[host] = zoneKey
		if rules, ok := allZones[zoneKey]; ok {
			zones[zoneKey] = rules
		}
	}
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
	return scopedSnapshot{
		generation: s.gen.Load(),
		global:     *s.global.Load(),
		zones:      zones,
		hostZone:   hostZone,
		routeZone:  routeZone,
	}
}

// patternHost extracts the host part of a route pattern ("host/path…" — the
// path always starts with "/", so the first slash delimits the host).
func patternHost(pattern string) string {
	if i := strings.IndexByte(pattern, '/'); i >= 0 {
		return pattern[:i]
	}
	return pattern
}

// concatGlobalRules collects the global ruleset from the given ConfigMaps: only
// those labeled `…/waf: global` AND living in podNamespace (the platform-owned
// baseline boundary). Mirrors the controller's reload + sortedDataValues.
func concatGlobalRules(cms []wafConfigMap, podNamespace string) string {
	var docs []string
	for _, cm := range cms {
		if cm.labels[WAFLabelKey] != wafRoleGlobal || cm.namespace != podNamespace {
			continue
		}
		docs = append(docs, sortedValues(cm.data)...)
	}
	return strings.Join(docs, "\n---\n")
}

// collectZoneRules collects zone ConfigMaps (any namespace) into
// zoneKey ("<ns>/<name>") -> concatenated YAML.
func collectZoneRules(cms []wafConfigMap) map[string]string {
	out := map[string]string{}
	for _, cm := range cms {
		if cm.labels[WAFLabelKey] != wafRoleZone {
			continue
		}
		key := cm.namespace + "/" + cm.name
		docs := sortedValues(cm.data)
		if existing := out[key]; existing != "" {
			docs = append([]string{existing}, docs...)
		}
		out[key] = strings.Join(docs, "\n---\n")
	}
	return out
}

// wafConfigMap is the minimal projection of a k8s ConfigMap the WAF reload needs.
type wafConfigMap struct {
	namespace string
	name      string
	labels    map[string]string
	data      map[string]string
}

func sortedValues(data map[string]string) []string {
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

func writeSortedMap(b *strings.Builder, m map[string]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte('\n')
	}
}

func etagOfString(s string) string {
	h := sha256.Sum256([]byte(s))
	return `"` + hex.EncodeToString(h[:16]) + `"`
}
