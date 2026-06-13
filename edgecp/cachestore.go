package edgecp

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Cache-override ConfigMap markers. The role values ("global"/"zone") are shared
// with the WAF and rate-limit labels.
const (
	CacheLabelKey = "parapet.moonrhythm.io/cache"
	// CacheZoneAnnotation binds an Ingress to a cache-override zone — bare id or
	// "ns/id". CROSS-NAMESPACE references are honored (the WAF model, NOT
	// ratelimit's same-namespace rule): an override set is stateless config, so
	// binding it cross-namespace applies the policy to the binding ingress's own
	// traffic only — there is no shared counter state a cross-tenant bind could
	// abuse.
	CacheZoneAnnotation = "parapet.moonrhythm.io/cache-zone"
)

// CacheStore holds everything the edge needs to apply ConfigMap-driven cache
// overrides: the global override documents (platform baseline, identical for
// every edge), tenant zone documents (keyed "<ns>/<name>"), and the path-aware
// route→zone bindings derived from Ingresses (cache-zone annotation). Documents
// stay []string end to end, like RateLimitStore: cacherule.Parse treats each
// ConfigMap data value as ONE YAML document and does not split "---".
//
// Unlike RateLimitStore there is no legacy host→zone map (cache overrides are a
// new feature, so every edge speaks the path-aware format) and no known-host
// list (overrides are stateless — there are no per-host buckets to collapse).
//
// Responses are scoped per edge by the caller (scoped()); same locking model as
// the other stores: lock-free reads via atomic pointers, mu held by writers and
// by scoped() for a consistent snapshot.
type CacheStore struct {
	mu        sync.RWMutex
	global    atomic.Pointer[[]string]
	zones     atomic.Pointer[map[string][]string] // zoneKey -> override documents
	routeZone atomic.Pointer[map[string]string]   // route pattern ("host/path[/]") -> zoneKey
	gen       atomic.Uint64
	curEtag   atomic.Pointer[string]
}

func NewCacheStore() *CacheStore {
	s := &CacheStore{}
	var g []string
	z := map[string][]string{}
	rz := map[string]string{}
	s.global.Store(&g)
	s.zones.Store(&z)
	s.routeZone.Store(&rz)
	et := etagOfString("")
	s.curEtag.Store(&et)
	return s
}

// SetGlobal replaces the global override documents (one per ConfigMap data
// value, deterministic order — see CacheReloader).
func (s *CacheStore) SetGlobal(docs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.global.Store(&docs)
	s.recompute()
}

// SetZones replaces the full zone registry (zoneKey -> override documents).
func (s *CacheStore) SetZones(zones map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zones.Store(&zones)
	s.recompute()
}

// SetIngressDerived replaces the path-aware route→zone binding (the only
// Ingress-derived input cache overrides need).
func (s *CacheStore) SetIngressDerived(routeZone map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routeZone.Store(&routeZone)
	s.recompute()
}

// recompute bumps the generation + etag when the combined content changes.
// Caller holds s.mu.
func (s *CacheStore) recompute() {
	et := etagOfString(s.fingerprint())
	if prev := s.curEtag.Load(); prev != nil && *prev == et {
		return
	}
	s.gen.Add(1)
	s.curEtag.Store(&et)
}

// Version is the store's full-content etag — an opaque change signal for the
// /v1/events stream (per-edge scoping happens at fetch time, not here).
func (s *CacheStore) Version() string { return *s.curEtag.Load() }

// fingerprint is a stable serialization of the full content. Documents are
// length-prefixed so doc-slice boundaries are unambiguous, mirroring
// RateLimitStore.fingerprint.
func (s *CacheStore) fingerprint() string {
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
	writeSortedMap(&b, *s.routeZone.Load())
	return b.String()
}

// cacheScopedSnapshot is the per-edge cache-override payload: global (shared) +
// only the zones and route bindings for hosts the edge may serve.
type cacheScopedSnapshot struct {
	generation uint64
	global     []string
	zones      map[string][]string
	routeZone  map[string]string
}

// scoped builds the response for an edge, mirroring RateLimitStore.scoped: read
// under the lock so the fields are one consistent snapshot.
func (s *CacheStore) scoped(allow func(host string) bool) cacheScopedSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	allZones := *s.zones.Load()
	allRouteZone := *s.routeZone.Load()

	zones := map[string][]string{}
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
	return cacheScopedSnapshot{
		generation: s.gen.Load(),
		global:     *s.global.Load(),
		zones:      zones,
		routeZone:  routeZone,
	}
}

// collectGlobalCacheDocs collects the global override documents from the given
// ConfigMaps: only those labeled `…/cache: global` AND living in podNamespace
// (the platform-owned baseline boundary), in deterministic namespace/name +
// data-key order.
func collectGlobalCacheDocs(cms []wafConfigMap, podNamespace string) []string {
	var globals []wafConfigMap
	for _, cm := range cms {
		if cm.labels[CacheLabelKey] != wafRoleGlobal || cm.namespace != podNamespace {
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

// collectZoneCacheDocs collects zone ConfigMaps (any namespace) into
// zoneKey ("<ns>/<name>") -> override documents.
func collectZoneCacheDocs(cms []wafConfigMap) map[string][]string {
	out := map[string][]string{}
	for _, cm := range cms {
		if cm.labels[CacheLabelKey] != wafRoleZone {
			continue
		}
		key := cm.namespace + "/" + cm.name
		out[key] = append(out[key], sortedValues(cm.data)...)
	}
	return out
}
