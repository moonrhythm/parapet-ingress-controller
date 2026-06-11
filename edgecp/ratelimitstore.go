package edgecp

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Rate-limit ConfigMap markers — mirror the controller's
// (controller_ratelimit.go). The role values ("global"/"zone") are shared with
// the WAF label.
const (
	RateLimitLabelKey = "parapet.moonrhythm.io/ratelimit"
	// RateLimitZoneAnnotation binds an Ingress to a rate-limit zone — SAME
	// NAMESPACE only, mirroring plugin.RateLimitZone: zones carry shared
	// counter state, so a cross-namespace bind would let any tenant burn
	// another tenant's per-key budgets.
	RateLimitZoneAnnotation = "parapet.moonrhythm.io/ratelimit-zone"
)

// RateLimitStore holds everything the edge needs to enforce ConfigMap-driven
// rate limits: the global limit documents (platform baseline, identical for
// every edge), tenant zone documents (keyed "<ns>/<name>"), the zone bindings
// derived from Ingresses (ratelimit-zone annotation, same-namespace only — the
// path-aware routeZone map plus the legacy host→zoneKey map older edges still
// consume), and the known-host list (every Ingress rule host) the edge wires as
// the Limiter's host-key collapser. Unlike the WafStore, documents stay
// []string end to end: ratelimitrule.Parse treats each ConfigMap data value as
// ONE YAML document and does not split "---", so the WAF's concatenated-string
// format would silently drop every document after the first.
//
// Responses are scoped per edge by the caller (scoped()); same locking model
// as WafStore: lock-free reads via atomic pointers, mu held by writers and by
// scoped() for a consistent snapshot.
type RateLimitStore struct {
	mu        sync.RWMutex
	global    atomic.Pointer[[]string]
	zones     atomic.Pointer[map[string][]string] // zoneKey -> limit documents
	hostZone  atomic.Pointer[map[string]string]   // lowercased host -> zoneKey (legacy, pre-path-aware edges)
	routeZone atomic.Pointer[map[string]string]   // route pattern ("host/path[/]") -> zoneKey
	hosts     atomic.Pointer[[]string]            // sorted known hosts (host-key collapse)
	gen       atomic.Uint64
	curEtag   atomic.Pointer[string]
}

func NewRateLimitStore() *RateLimitStore {
	s := &RateLimitStore{}
	var g []string
	z := map[string][]string{}
	h := map[string]string{}
	rz := map[string]string{}
	var hosts []string
	s.global.Store(&g)
	s.zones.Store(&z)
	s.hostZone.Store(&h)
	s.routeZone.Store(&rz)
	s.hosts.Store(&hosts)
	et := etagOfString("")
	s.curEtag.Store(&et)
	return s
}

// SetGlobal replaces the global limit documents (one per ConfigMap data value,
// deterministic order — see RateLimitReloader).
func (s *RateLimitStore) SetGlobal(docs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.global.Store(&docs)
	s.recompute()
}

// SetZones replaces the full zone registry (zoneKey -> limit documents).
func (s *RateLimitStore) SetZones(zones map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zones.Store(&zones)
	s.recompute()
}

// SetIngressDerived replaces all Ingress-derived inputs — the legacy host→
// zoneKey binding, the path-aware routeZone binding, and the known-host list —
// in one recompute, so a single Ingress reload can't be observed half-applied.
func (s *RateLimitStore) SetIngressDerived(hostZone, routeZone map[string]string, hosts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostZone.Store(&hostZone)
	s.routeZone.Store(&routeZone)
	s.hosts.Store(&hosts)
	s.recompute()
}

// recompute bumps the generation + etag when the combined content changes.
// Caller holds s.mu.
func (s *RateLimitStore) recompute() {
	et := etagOfString(s.fingerprint())
	if prev := s.curEtag.Load(); prev != nil && *prev == et {
		return
	}
	s.gen.Add(1)
	s.curEtag.Store(&et)
}

// Version is the store's full-content etag — an opaque change signal for the
// /v1/events stream (per-edge scoping happens at fetch time, not here).
func (s *RateLimitStore) Version() string { return *s.curEtag.Load() }

// fingerprint is a stable serialization of the full content. Documents are
// length-prefixed so doc-slice boundaries are unambiguous (["a","bc"] vs
// ["ab","c"]), mirroring the controller's fingerprintDocs.
func (s *RateLimitStore) fingerprint() string {
	var b strings.Builder
	writeDocs := func(docs []string) {
		for _, d := range docs {
			b.WriteString(strconv.Itoa(len(d)))
			b.WriteByte(':')
			b.WriteString(d)
		}
	}
	writeDocs(*s.global.Load())
	b.WriteByte(0)
	zones := *s.zones.Load()
	zoneKeys := make([]string, 0, len(zones))
	for k := range zones {
		zoneKeys = append(zoneKeys, k)
	}
	sort.Strings(zoneKeys)
	for _, k := range zoneKeys {
		b.WriteString(k)
		b.WriteByte(1)
		writeDocs(zones[k])
		b.WriteByte(1)
	}
	b.WriteByte(0)
	writeSortedMap(&b, *s.hostZone.Load())
	b.WriteByte(0)
	writeSortedMap(&b, *s.routeZone.Load())
	b.WriteByte(0)
	for _, h := range *s.hosts.Load() {
		b.WriteString(h)
		b.WriteByte(1)
	}
	return b.String()
}

// rlScopedSnapshot is the per-edge rate-limit payload: global (shared) + only
// the zones, host bindings, and known hosts for hosts the edge may serve.
type rlScopedSnapshot struct {
	generation uint64
	global     []string
	zones      map[string][]string
	hostZone   map[string]string
	routeZone  map[string]string
	hosts      []string
}

// scoped builds the response for an edge, mirroring WafStore.scoped: read
// under the lock so the five fields are one consistent snapshot.
func (s *RateLimitStore) scoped(allow func(host string) bool) rlScopedSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	allZones := *s.zones.Load()
	allHostZone := *s.hostZone.Load()
	allRouteZone := *s.routeZone.Load()
	allHosts := *s.hosts.Load()

	hostZone := map[string]string{}
	zones := map[string][]string{}
	for host, zoneKey := range allHostZone {
		if !allow(host) {
			continue
		}
		hostZone[host] = zoneKey
		if docs, ok := allZones[zoneKey]; ok {
			zones[zoneKey] = docs
		}
	}
	routeZone := map[string]string{}
	for pattern, zoneKey := range allRouteZone {
		if !allow(patternHost(pattern)) {
			continue
		}
		routeZone[pattern] = zoneKey
		if docs, ok := allZones[zoneKey]; ok {
			zones[zoneKey] = docs
		}
	}
	hosts := make([]string, 0, len(allHosts))
	for _, h := range allHosts {
		if allow(h) {
			hosts = append(hosts, h)
		}
	}
	return rlScopedSnapshot{
		generation: s.gen.Load(),
		global:     *s.global.Load(),
		zones:      zones,
		hostZone:   hostZone,
		routeZone:  routeZone,
		hosts:      hosts,
	}
}

// collectGlobalLimitDocs collects the global limit documents from the given
// ConfigMaps: only those labeled `…/ratelimit: global` AND living in
// podNamespace (the platform-owned baseline boundary), in deterministic
// namespace/name + data-key order — limit evaluation order depends on it.
func collectGlobalLimitDocs(cms []wafConfigMap, podNamespace string) []string {
	var globals []wafConfigMap
	for _, cm := range cms {
		if cm.labels[RateLimitLabelKey] != wafRoleGlobal || cm.namespace != podNamespace {
			continue
		}
		globals = append(globals, cm)
	}
	sort.Slice(globals, func(i, j int) bool {
		if globals[i].namespace != globals[j].namespace {
			return globals[i].namespace < globals[j].namespace
		}
		return globals[i].name < globals[j].name
	})
	var docs []string
	for _, cm := range globals {
		docs = append(docs, sortedValues(cm.data)...)
	}
	return docs
}

// collectZoneLimitDocs collects zone ConfigMaps (any namespace) into
// zoneKey ("<ns>/<name>") -> limit documents.
func collectZoneLimitDocs(cms []wafConfigMap) map[string][]string {
	out := map[string][]string{}
	for _, cm := range cms {
		if cm.labels[RateLimitLabelKey] != wafRoleZone {
			continue
		}
		key := cm.namespace + "/" + cm.name
		out[key] = append(out[key], sortedValues(cm.data)...)
	}
	return out
}
