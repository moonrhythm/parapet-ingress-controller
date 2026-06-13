// Package cacherule parses the YAML override documents carried in cache
// ConfigMaps (the global set and per-zone sets) and runs them against the edge
// response cache.
//
// It mirrors ratelimitrule's split: Parse is the thin YAML-to-DTO layer, and
// Ruleset.SetOverrides is the single source of truth for the heavier validation
// (empty/duplicate/over-long id, bad enums, ttl bounds, CEL compilation) and for
// the all-or-nothing compile — a bad batch keeps the last-good set live. Unlike
// rate limiting the rules carry no live counter state, so there is no
// counter-preservation machinery: a Ruleset is just a hot-swappable compiled set
// that feeds parapet/pkg/cache's two per-request hooks (Options.Cacheable for
// bypass rules, Options.Override for force rules).
package cacherule

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Document is the YAML shape of a cache ConfigMap data value.
type Document struct {
	Overrides []Override `yaml:"overrides"`
}

// Override is one cache-policy override. Defaults and enums are
// resolved/validated by Ruleset.SetOverrides, not here.
type Override struct {
	// ID identifies the override within its set and labels its metric series, so
	// it must be unique, at most 63 chars, and use only [A-Za-z0-9._-] (a "/" or
	// ":" would make the parapet_cache_override_total name ambiguous).
	ID string `yaml:"id"`
	// Action is "cache" (default; force a caching policy onto the fill via
	// Options.Override) or "bypass" (the request skips the cache entirely via
	// Options.Cacheable → false). A bypass takes precedence over any force, since
	// the cache evaluates Cacheable before it considers a fill.
	Action string `yaml:"action"`
	// Filter is an optional CEL expression (the WAF's expression surface — same
	// request.* variables and helper functions, via waf.NewPredicate) that scopes
	// the override: empty means "every request", otherwise it applies only when
	// the expression is true. request.body is always "" here (the cache does not
	// buffer the request body); a geo reference (request.country/asn) without the
	// GeoIP database simply never matches. A runtime eval error biases toward NOT
	// caching (see Ruleset.MatchBypass / Force) — the deliberate inverse of the
	// rate limiter's fail-open, because caching is the dangerous action. A bad
	// expression is rejected at load (the whole batch).
	Filter string `yaml:"filter"`
	// TTL is the forced freshness lifetime (a Go duration, >= 1s). Required for
	// action=cache (parapet treats a non-positive TTL as "don't force"); rejected
	// for action=bypass.
	TTL string `yaml:"ttl"`
	// Policy selects how far the force reaches over the origin's Cache-Control
	// (parapet's OverrideMode): "conservative" (fill only missing freshness),
	// "balanced" (default; force but refuse unsafe-to-share responses), or
	// "aggressive" (override almost everything, including the Authorization gate
	// — a cross-user-leak risk; see CACHE.md). action=cache only.
	Policy string `yaml:"policy"`
	// StaleWhileRevalidate / StaleIfError force the RFC 5861 windows (Go
	// durations) for this rule's fills. They ride the forced policy, so they
	// require a ttl. action=cache only.
	StaleWhileRevalidate string `yaml:"stale_while_revalidate"`
	StaleIfError         string `yaml:"stale_if_error"`
	// Status narrows a force to specific origin response statuses (the Override
	// hook sees the response, unlike CEL). Empty means "every cacheable status
	// the cache already accepts". Ignored for action=bypass (no response yet when
	// Cacheable runs).
	Status []int `yaml:"status"`
	// Mode is "enforce" (default) or "shadow": shadow evaluates and counts the
	// override (parapet_cache_override_total{result="shadow"}) but never changes
	// caching, so a rule can be validated against live traffic before it takes
	// effect.
	Mode string `yaml:"mode"`
	// Priority orders force rules; the first matching cache rule wins (lower
	// number first, declaration order breaks ties). Default 100. Bypass rules are
	// not ordered against each other.
	Priority int `yaml:"priority"`
}

// Parse parses one or more YAML override documents (each ConfigMap data value is
// one document) and returns the concatenated []Override. A YAML error in any
// document is collected and returned joined; the caller (SetOverrides) rejects
// the whole batch on any error, so a bad document never partially applies.
func Parse(docs ...string) ([]Override, error) {
	var out []Override
	var errs []error
	for _, doc := range docs {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var d Document
		if err := yaml.Unmarshal([]byte(doc), &d); err != nil {
			errs = append(errs, fmt.Errorf("cache: parse document: %w", err))
			continue
		}
		out = append(out, d.Overrides...)
	}
	return out, errors.Join(errs...)
}
