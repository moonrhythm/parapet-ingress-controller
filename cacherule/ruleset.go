package cacherule

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/moonrhythm/parapet/pkg/cache"
	"github.com/moonrhythm/parapet/pkg/waf"
)

const (
	maxIDLen = 63

	// minTTL bounds a forced freshness lifetime. A sub-second forced TTL is
	// almost always a units mistake (e.g. "30" parsed as 30ns) and would store an
	// entry that is already stale.
	minTTL = time.Second

	defaultPriority = 100
)

// metric result labels (parapet_cache_override_total{result}). applied = the
// override changed caching for an in-scope request; shadow = matched but mode
// withheld the effect; error = the filter eval errored (the override biased
// toward not-caching). A rule the filter excludes is not counted at all.
const (
	resultApplied = "applied"
	resultShadow  = "shadow"
	resultError   = "error"
)

// ObserveFunc records one in-scope override decision. nil disables metrics.
type ObserveFunc func(result string)

type action uint8

const (
	actionCache action = iota
	actionBypass
)

type mode uint8

const (
	modeEnforce mode = iota
	modeShadow
)

// compiledOverride is one override ready for the request path: enums resolved,
// CEL compiled, observe handle pre-resolved. Immutable after the set is
// published.
type compiledOverride struct {
	id       string
	action   action
	filter   *waf.Predicate // nil ⇒ always matches (no CEL gate)
	mode     mode
	priority int
	observe  ObserveFunc // nil when no Observe factory is wired

	// force fields (action == actionCache only)
	ttl    time.Duration
	swr    time.Duration
	sie    time.Duration
	omode  cache.OverrideMode
	status map[int]struct{} // nil ⇒ any cacheable status
}

// ruleset is one immutable compiled batch, swapped atomically into the Ruleset.
// bypass keeps declaration order; force is sorted by priority. The request path
// loads the pointer once and evaluates that whole set.
type ruleset struct {
	bypass      []compiledOverride // action == bypass
	force       []compiledOverride // action == cache, priority-ordered
	source      []Override         // normalized input, for introspection
	needsFilter bool               // any rule carries a CEL filter
}

// Ruleset is a hot-swappable set of cache overrides — the runtime for both the
// global instance and each zone. Configure the exported fields before the first
// SetOverrides; they are read at compile time, not per request.
//
// An empty Ruleset (no SetOverrides yet, or an empty batch) matches nothing:
// MatchBypass returns false and Force returns nil, so the cache honors the
// origin exactly as if no overrides existed.
type Ruleset struct {
	set atomic.Pointer[ruleset]
	mu  sync.Mutex // serializes SetOverrides (validate+compile+swap)

	// NamePrefix scopes the metric name of every rule:
	// parapet_cache_override_total{name="<NamePrefix>:<id>"}. The edge uses
	// "global" and "zone:<ns>/<name>", disjoint name spaces.
	NamePrefix string

	// Observe builds the per-rule decision observer (e.g.
	// metric/observe.CacheOverride). Resolved once per rule at SetOverrides, so
	// the request path is lookup-free. nil disables decision metrics. The result
	// type is the unnamed func(string) (not ObserveFunc) so a leaf metric package
	// can supply it without importing this one — the same boundary the rate
	// limiter keeps with parapet's ratelimit.ObserveFunc.
	Observe func(name, action string) func(result string)

	// FilterCostLimit caps CEL evaluator cost per filter evaluation (0 ⇒ the
	// parapet WAF default). FilterDisableMacros refuses CEL macros. Both mirror
	// the edge WAF's posture; read at SetOverrides, not per request.
	FilterCostLimit     uint64
	FilterDisableMacros bool
}

// Overrides returns the normalized overrides of the live set (defaults
// resolved), in declaration order. Nil when nothing is loaded.
func (rs *Ruleset) Overrides() []Override {
	s := rs.set.Load()
	if s == nil {
		return nil
	}
	return s.source
}

// NeedsFilter reports whether the live set carries any CEL filter — the edge
// uses it to skip building the request snapshot for filterless sets.
func (rs *Ruleset) NeedsFilter() bool {
	s := rs.set.Load()
	return s != nil && s.needsFilter
}

// SetOverrides validates and compiles the batch, then atomically swaps it in.
// All-or-nothing: any invalid override rejects the whole batch and the previous
// good set stays live, so a bad ConfigMap edit can't change caching unexpectedly.
func (rs *Ruleset) SetOverrides(overrides []Override) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	var errs []error
	seen := make(map[string]struct{}, len(overrides))
	var bypass, force []compiledOverride
	source := make([]Override, 0, len(overrides))
	needsFilter := false

	for i, ov := range overrides {
		c, norm, err := rs.compile(ov)
		if err != nil {
			errs = append(errs, fmt.Errorf("cache: override[%d] %q: %w", i, ov.ID, err))
			continue
		}
		if _, dup := seen[c.id]; dup {
			errs = append(errs, fmt.Errorf("cache: override[%d] %q: duplicate id", i, ov.ID))
			continue
		}
		seen[c.id] = struct{}{}
		if c.filter != nil {
			needsFilter = true
		}
		if c.action == actionBypass {
			bypass = append(bypass, c)
		} else {
			force = append(force, c)
		}
		source = append(source, norm)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}

	// Stable sort keeps declaration order as the tie-break, so "first match wins"
	// is deterministic for equal priorities.
	sort.SliceStable(force, func(i, j int) bool { return force[i].priority < force[j].priority })

	rs.set.Store(&ruleset{bypass: bypass, force: force, source: source, needsFilter: needsFilter})
	return nil
}

// compile validates one override and builds its compiled form plus the
// normalized (defaults-resolved) source copy.
func (rs *Ruleset) compile(ov Override) (compiledOverride, Override, error) {
	var errs []error

	if err := validateID(ov.ID); err != nil {
		errs = append(errs, err)
	}

	var act action
	switch ov.Action {
	case "", "cache":
		act, ov.Action = actionCache, "cache"
	case "bypass":
		act = actionBypass
	default:
		errs = append(errs, fmt.Errorf("unknown action %q (want cache|bypass)", ov.Action))
	}

	var m mode
	switch ov.Mode {
	case "", "enforce":
		m, ov.Mode = modeEnforce, "enforce"
	case "shadow":
		m = modeShadow
	default:
		errs = append(errs, fmt.Errorf("unknown mode %q (want enforce|shadow)", ov.Mode))
	}

	if ov.Priority == 0 {
		ov.Priority = defaultPriority
	}

	c := compiledOverride{
		id:       ov.ID,
		action:   act,
		mode:     m,
		priority: ov.Priority,
	}

	if act == actionCache {
		c.ttl, c.swr, c.sie, c.omode, c.status = rs.compileForce(ov, &errs)
	} else {
		// bypass: the force-only fields are meaningless and silently honoring them
		// would mask an authoring mistake. Reject any that are set.
		if strings.TrimSpace(ov.TTL) != "" || strings.TrimSpace(ov.Policy) != "" ||
			strings.TrimSpace(ov.StaleWhileRevalidate) != "" || strings.TrimSpace(ov.StaleIfError) != "" ||
			len(ov.Status) > 0 {
			errs = append(errs, errors.New("ttl/policy/status/stale_* are not valid for action=bypass"))
		}
	}

	// Filter compiles into a waf.Predicate over the WAF's request model. A bad
	// expression joins errs, so an invalid filter rejects the whole batch.
	var filter *waf.Predicate
	ov.Filter = strings.TrimSpace(ov.Filter)
	if ov.Filter != "" {
		p, err := waf.NewPredicate(ov.Filter, rs.filterOptions()...)
		if err != nil {
			errs = append(errs, fmt.Errorf("filter: %w", err))
		} else {
			filter = p
		}
	}
	c.filter = filter

	if err := errors.Join(errs...); err != nil {
		return compiledOverride{}, Override{}, err
	}

	if rs.Observe != nil {
		c.observe = rs.Observe(rs.NamePrefix+":"+ov.ID, ov.Action)
	}
	return c, ov, nil
}

// compileForce validates and resolves the action=cache fields. It appends to
// errs and returns the resolved values (zero on error — the batch is rejected).
func (rs *Ruleset) compileForce(ov Override, errs *[]error) (ttl, swr, sie time.Duration, omode cache.OverrideMode, status map[int]struct{}) {
	if strings.TrimSpace(ov.TTL) == "" {
		*errs = append(*errs, errors.New("ttl is required for action=cache"))
	} else if d, err := time.ParseDuration(ov.TTL); err != nil {
		*errs = append(*errs, fmt.Errorf("invalid ttl: %w", err))
	} else if d < minTTL {
		*errs = append(*errs, fmt.Errorf("ttl %s below minimum %s", d, minTTL))
	} else {
		ttl = d
	}

	switch ov.Policy {
	case "", "balanced":
		omode = cache.OverrideBalanced
	case "conservative":
		omode = cache.OverrideConservative
	case "aggressive":
		omode = cache.OverrideAggressive
	default:
		*errs = append(*errs, fmt.Errorf("unknown policy %q (want conservative|balanced|aggressive)", ov.Policy))
	}

	swr = parseStaleWindow("stale_while_revalidate", ov.StaleWhileRevalidate, errs)
	sie = parseStaleWindow("stale_if_error", ov.StaleIfError, errs)

	if len(ov.Status) > 0 {
		status = make(map[int]struct{}, len(ov.Status))
		for _, s := range ov.Status {
			if s < 100 || s > 599 {
				*errs = append(*errs, fmt.Errorf("invalid status %d (want 100..599)", s))
				continue
			}
			status[s] = struct{}{}
		}
	}
	return ttl, swr, sie, omode, status
}

func parseStaleWindow(field, raw string, errs *[]error) time.Duration {
	if strings.TrimSpace(raw) == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("invalid %s: %w", field, err))
		return 0
	}
	if d < 0 {
		*errs = append(*errs, fmt.Errorf("%s must be >= 0", field))
		return 0
	}
	return d
}

// filterOptions builds the waf.NewPredicate options from the Ruleset's filter
// knobs. Zero values leave the parapet WAF defaults, so an unconfigured Ruleset
// compiles filters exactly like a default edge WAF rule.
func (rs *Ruleset) filterOptions() []waf.PredicateOption {
	var opts []waf.PredicateOption
	if rs.FilterCostLimit > 0 {
		opts = append(opts, waf.WithPredicateCostLimit(rs.FilterCostLimit))
	}
	if rs.FilterDisableMacros {
		opts = append(opts, waf.WithPredicateDisableMacros())
	}
	return opts
}

// MatchBypass reports whether this set bypasses the cache for r. getInput
// returns the shared request snapshot (built at most once per request by the
// caller, across the global + zone sets). A bypass rule whose filter ERRORS is
// treated as matched — the fail-safe direction: caching is the dangerous action,
// so an error biases toward not caching. A shadow rule that would bypass is
// counted but does not actually bypass.
func (rs *Ruleset) MatchBypass(r *http.Request, getInput func() waf.Input) bool {
	s := rs.set.Load()
	if s == nil || len(s.bypass) == 0 {
		return false
	}
	for i := range s.bypass {
		b := &s.bypass[i]
		matched, errored := true, false
		if b.filter != nil {
			ok, err := b.filter.Eval(r.Context(), getInput())
			if err != nil {
				matched, errored = true, true // fail toward not caching
			} else {
				matched = ok
			}
		}
		if !matched {
			continue
		}
		if b.mode == modeShadow {
			observe(b.observe, resultShadow)
			continue
		}
		if errored {
			observe(b.observe, resultError)
		} else {
			observe(b.observe, resultApplied)
		}
		return true
	}
	return false
}

// Force returns the forced caching policy for r and the origin response status,
// or (nil, false) to honor the origin. getInput is the shared request snapshot.
// Rules are tried in priority order; the first clean match wins. A rule whose
// filter ERRORS is SKIPPED (honor the origin) — the fail-safe direction for a
// force, since applying a force on an error could cache shared/per-user content.
// A shadow rule that would apply is counted and skipped (a lower-priority real
// rule may still apply).
func (rs *Ruleset) Force(r *http.Request, status int, getInput func() waf.Input) (*cache.Override, bool) {
	s := rs.set.Load()
	if s == nil || len(s.force) == 0 {
		return nil, false
	}
	for i := range s.force {
		f := &s.force[i]
		if f.status != nil {
			if _, ok := f.status[status]; !ok {
				continue
			}
		}
		matched := true
		if f.filter != nil {
			ok, err := f.filter.Eval(r.Context(), getInput())
			if err != nil {
				observe(f.observe, resultError)
				continue // fail toward not caching: skip the force
			}
			matched = ok
		}
		if !matched {
			continue
		}
		if f.mode == modeShadow {
			observe(f.observe, resultShadow)
			continue
		}
		observe(f.observe, resultApplied)
		return &cache.Override{
			TTL:                  f.ttl,
			StaleWhileRevalidate: f.swr,
			StaleIfError:         f.sie,
			Mode:                 f.omode,
		}, true
	}
	return nil, false
}

func observe(fn ObserveFunc, result string) {
	if fn != nil {
		fn(result)
	}
}

func validateID(id string) error {
	if id == "" {
		return errors.New("id is required")
	}
	if len(id) > maxIDLen {
		return fmt.Errorf("id longer than %d chars", maxIDLen)
	}
	for i := 0; i < len(id); i++ {
		switch c := id[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
		default:
			// "/" or ":" would make the metric name ambiguous against the
			// "<prefix>:<id>" scheme.
			return fmt.Errorf("id contains %q (want [A-Za-z0-9._-])", c)
		}
	}
	return nil
}
