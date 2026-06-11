// Package ratelimitrule parses the YAML limit documents carried in rate-limit
// ConfigMaps (the global set and per-zone sets) and runs them.
//
// It mirrors wafrule's split: Parse is the thin YAML-to-DTO layer, and
// Limiter.SetLimits is the single source of truth for the heavier validation
// (empty/duplicate/over-long id, bad enums, window bounds) and for the
// all-or-nothing compile — a bad batch keeps the last-good set live. Unlike the
// WAF there is no parapet-side SetRules equivalent, so this package also owns
// the runtime: a hot-swappable compiled set evaluated per request.
package ratelimitrule

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Document is the YAML shape of a rate-limit ConfigMap data value.
type Document struct {
	Limits []Limit `yaml:"limits"`
}

// Keys is a limit's bucket-dimension spec: one or more characteristics whose
// per-request values compose into the bucket key. YAML accepts a scalar
// ("key: ip", "key: header:x-api-key") or a sequence
// ("key: [ip, header:x-api-key]").
type Keys []string

// UnmarshalYAML accepts a scalar (one characteristic) or a sequence.
func (k *Keys) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var s string
		if err := value.Decode(&s); err != nil {
			return err
		}
		*k = Keys{s}
		return nil
	case yaml.SequenceNode:
		var ss []string
		if err := value.Decode(&ss); err != nil {
			return err
		}
		*k = ss
		return nil
	default:
		return fmt.Errorf("key must be a string or a list of strings")
	}
}

// Limit is one rate limit. Defaults and enums are resolved/validated by
// Limiter.SetLimits, not here.
type Limit struct {
	// ID identifies the limit within its set and labels its metric series, so it
	// must be unique, at most 63 chars, and use only [A-Za-z0-9._-] (a "/" or ":"
	// would make the parapet_ratelimit_total name ambiguous).
	ID string `yaml:"id"`
	// Key lists the characteristics composed into the bucket key (default
	// ["ip"]): "ip" (IPv6 aggregated per /64), "host", "asn" / "country"
	// (GeoIP; require the resolver to be wired), "header:<name>",
	// "cookie:<name>". "ip-host" is an alias for ip + host.
	Key Keys `yaml:"key"`
	// Rate is the max requests admitted per Window per key. Required, > 0.
	Rate int `yaml:"rate"`
	// Window is a Go duration string ("10s", "1m", "1h"), bounded to 1s..1h. The
	// bound caps the per-key map's retention to today's worst opt-in exposure
	// (the per-hour annotation limiter).
	Window string `yaml:"window"`
	// Algorithm is "fixed" (default; window-aligned counter, admits up to 2x Rate
	// across a boundary) or "sliding" (weighted two-window blend, smooths the
	// boundary burst).
	Algorithm string `yaml:"algorithm"`
	// Mode is "enforce" (default) or "shadow": shadow takes and counts decisions
	// (parapet_ratelimit_total{result="limited"}) but never rejects, so a limit
	// can be sized from live traffic before it is enforced.
	Mode string `yaml:"mode"`
	// Status is the rejection status: 429 (default) or 503. Restricted so the
	// status-derived parapet_rejected_requests reason mapping stays truthful.
	Status int `yaml:"status"`
	// Message is the rejection body (default "Too Many Requests").
	Message string `yaml:"message"`
	// Exclude lists CIDRs whose client IP skips this limit (health checkers,
	// trusted probes).
	Exclude []string `yaml:"exclude"`
}

// Parse parses one or more YAML limit documents (each ConfigMap data value is
// one document) and returns the concatenated []Limit. A YAML error in any
// document is collected and returned joined; the caller (SetLimits) rejects the
// whole batch on any error, so a bad document never partially applies.
func Parse(docs ...string) ([]Limit, error) {
	var out []Limit
	var errs []error
	for _, doc := range docs {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var d Document
		if err := yaml.Unmarshal([]byte(doc), &d); err != nil {
			errs = append(errs, fmt.Errorf("ratelimit: parse document: %w", err))
			continue
		}
		out = append(out, d.Limits...)
	}
	return out, errors.Join(errs...)
}
