package edge

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/moonrhythm/parapet/pkg/waf"

	"github.com/moonrhythm/parapet-ingress-controller/cacherule"
	"github.com/moonrhythm/parapet-ingress-controller/metric/observe"
)

// EdgeCacheOverride holds the compiled global override set plus tenant zones
// fetched from the control plane, and exposes them as the two per-request hooks
// parapet/pkg/cache consults: Cacheable (bypass rules) and Override (force
// rules). It reuses cacherule — the same parser/runtime the spec defines — so an
// override shapes caching identically wherever it is evaluated.
//
// Eval order mirrors the WAF/rate limiter: global first (authoritative), then
// the zone bound to the request route. Zone resolution is PATH-AWARE (the same
// zoneMatcher: the controller's own route patterns on a real http.ServeMux).
// Unlike the rate limiter, zone binding allows CROSS-NAMESPACE references (the
// WAF model): an override set is stateless config, so binding tenant A's zone to
// tenant B's ingress applies A's policy to B's own traffic only — there is no
// shared counter state to abuse. Bypass is a union (global OR zone, most
// restrictive wins); force is first-match global-before-zone.
type EdgeCacheOverride struct {
	global  *cacherule.Ruleset
	zones   atomic.Pointer[map[string]*cacherule.Ruleset] // zoneKey -> compiled zone
	matcher atomic.Pointer[zoneMatcher]                   // host+path -> zoneKey (core ServeMux semantics)

	newZone func(key string) *cacherule.Ruleset
	country func(*http.Request) string
	asn     func(*http.Request) int64

	generation atomic.Uint64

	mu   sync.Mutex
	etag string
}

// NewEdgeCacheOverride builds an empty edge cache-override runtime. country/asn
// are the GeoIP resolvers (the same ones the edge WAF/rate limiter use) used to
// populate request.country/request.asn for a filter; nil leaves those fields ""
// / 0 (a geo reference simply never matches), never a load error.
func NewEdgeCacheOverride(country func(*http.Request) string, asn func(*http.Request) int64) *EdgeCacheOverride {
	e := &EdgeCacheOverride{country: country, asn: asn}
	newRuleset := func(prefix string) *cacherule.Ruleset {
		return &cacherule.Ruleset{
			NamePrefix: prefix,
			// observe (not metric) keeps the edge binaries off the metric package,
			// the same boundary as the edge WAF/rate-limit observers.
			Observe: observe.CacheOverride,
		}
	}
	e.global = newRuleset("global")
	e.newZone = func(key string) *cacherule.Ruleset { return newRuleset("zone:" + key) }
	empty := map[string]*cacherule.Ruleset{}
	e.zones.Store(&empty)
	e.matcher.Store(newZoneMatcher(nil, nil))
	return e
}

// Etag returns the ETag of the currently-loaded config (sent as If-None-Match).
func (e *EdgeCacheOverride) Etag() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.etag
}

// Update compiles and installs a fetched payload: the global override set, the
// zones, and the path-aware route→zone bindings. All-or-nothing PER set
// (SetOverrides keeps the last-good set on any invalid override); the zones map
// and matcher are swapped wholesale. The etag + generation advance only on a
// CLEAN apply, so a rejected set re-fetches (200, not 304) and re-warns each
// poll — keeping the degraded state visible, exactly like the WAF/rate-limit
// refreshers.
func (e *EdgeCacheOverride) Update(generation uint64, globalDocs []string, zoneDocs map[string][]string, routeZone map[string]string, etag string) error {
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	// global
	if ovs, err := cacherule.Parse(globalDocs...); err != nil {
		note(fmt.Errorf("global: %w", err))
	} else if err := e.global.SetOverrides(ovs); err != nil {
		note(fmt.Errorf("global: %w", err))
	}

	// zones: reuse the existing instance per key so a bad edit keeps last-good
	// without disturbing siblings.
	cur := e.zones.Load()
	newZones := make(map[string]*cacherule.Ruleset, len(zoneDocs))
	for key, docs := range zoneDocs {
		z := (*cur)[key]
		if z == nil {
			z = e.newZone(key)
		}
		if ovs, err := cacherule.Parse(docs...); err != nil {
			note(fmt.Errorf("zone %s: %w", key, err))
		} else if err := z.SetOverrides(ovs); err != nil {
			note(fmt.Errorf("zone %s: %w", key, err))
		}
		newZones[key] = z
	}
	e.zones.Store(&newZones)

	// No legacy host→zone map: cache overrides are a new feature, so every edge
	// understands the path-aware routeZone format and there is no old wire form
	// to fall back to.
	e.matcher.Store(newZoneMatcher(routeZone, nil))

	if firstErr == nil {
		e.mu.Lock()
		e.etag = etag
		e.mu.Unlock()
		e.generation.Store(generation)
	}
	return firstErr
}

// Cacheable implements parapet/pkg/cache's Options.Cacheable. It returns false
// (bypass the cache) when any matching bypass rule fires in the global OR the
// bound zone set. Runs on every GET/HEAD; a filterless set is a cheap pass.
func (e *EdgeCacheOverride) Cacheable(r *http.Request) bool {
	getInput := e.inputFor(r)
	if e.global.MatchBypass(r, getInput) {
		return false
	}
	if z := e.resolveZone(r); z != nil && z.MatchBypass(r, getInput) {
		return false
	}
	return true
}

// Override implements parapet/pkg/cache's Options.Override. It returns the first
// matching force policy — global rules before the bound zone's — or nil to honor
// the origin. Runs on a fill (miss), with the origin response status. header is
// part of the hook signature but unused: v1 narrows by status only.
func (e *EdgeCacheOverride) Override(r *http.Request, status int, _ http.Header) *cache.Override {
	getInput := e.inputFor(r)
	if ov, ok := e.global.Force(r, status, getInput); ok {
		return ov
	}
	if z := e.resolveZone(r); z != nil {
		if ov, ok := z.Force(r, status, getInput); ok {
			return ov
		}
	}
	return nil
}

// inputFor returns a closure that builds the WAF request snapshot at most once
// per hook call, shared across the global + zone evaluations. request.body is ""
// (the cache does not buffer the body); country/asn resolve through the same
// GeoIP funcs the edge WAF uses (nil ⇒ "" / 0).
func (e *EdgeCacheOverride) inputFor(r *http.Request) func() waf.Input {
	var input waf.Input
	built := false
	return func() waf.Input {
		if !built {
			var country string
			if e.country != nil {
				country = e.country(r)
			}
			var asn int64
			if e.asn != nil {
				asn = e.asn(r)
			}
			input = waf.NewInput(r, "", country, asn)
			built = true
		}
		return input
	}
}

// resolveZone returns the override set bound to the request's host+path, or nil.
// Host must already be normalized (host.StripPort + host.ToLower upstream).
func (e *EdgeCacheOverride) resolveZone(r *http.Request) *cacherule.Ruleset {
	m := e.matcher.Load()
	if m == nil {
		return nil
	}
	key, ok := m.resolve(r)
	if !ok {
		return nil
	}
	zs := e.zones.Load()
	if zs == nil {
		return nil
	}
	return (*zs)[key]
}
