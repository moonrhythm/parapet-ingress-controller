// Package transformrule parses the YAML transform documents carried in
// transform ConfigMaps (one per (project, location) zone) and runs them as a
// per-Ingress request/response mutation layer.
//
// It mirrors ratelimitrule's split shape: the YAML DTO (Document/Rule/Op) is the
// wire contract written by the deployer, and Parse is the single source of truth
// for compiling a zone — validating each rule, compiling its CEL Filter via the
// parapet lib waf.NewPredicate (the SAME request.* surface WAF and ratelimit
// use), and building an ordered op pipeline. Compilation is ALL-OR-NOTHING: one
// bad rule rejects the whole Document, so the controller keeps the last-good
// Zone live (no partial apply). A filter that errors at EVAL (not compile) skips
// only that one rule at request time — the safe bias for a mutation layer.
//
// Two physical mutation seams (SPEC §4.1):
//   - request phase: an http.Handler wrapper that mutates r (headers, URL path/
//     query) before proxying, or short-circuits with an HTTP redirect.
//   - response phase: a headers.ResponseInterceptor whose callback fires lazily
//     at the upstream's first WriteHeader, editing response headers and
//     overriding the status before they go on the wire.
//
// The one documented exception is the dual-seam `cors` op (SPEC §2.3): authored
// in a response-phase rule but mounted as a standalone request-spanning
// cors.CORS middleware, so its OPTIONS preflight short-circuit fires at request
// time. Validation requires it to be the sole op in its rule.
package transformrule

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/moonrhythm/parapet/pkg/cors"
	"github.com/moonrhythm/parapet/pkg/headers"
	"github.com/moonrhythm/parapet/pkg/waf"
	"golang.org/x/net/http/httpguts"
	"gopkg.in/yaml.v3"
)

// Document is the YAML shape of a transform ConfigMap data value. The root key
// is `transforms`, matching the api TransformSet.Transforms field and the
// deployer's wire marshal (SPEC §5.2).
type Document struct {
	Transforms []Rule `yaml:"transforms"`
}

// Rule is one phase + optional CEL scope + an ordered list of ops of that phase.
// The snake_case yaml tags ARE the parapet wire contract; do not rename them.
type Rule struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Phase       string `yaml:"phase"`    // "request" | "response"
	Filter      string `yaml:"filter"`   // CEL over request.*; "" = always; eval-error => skip
	Ops         []Op   `yaml:"ops"`      // applied in array order; all belong to Phase
	Mode        string `yaml:"mode"`     // "" = enforce | "shadow" (match+count, apply nothing)
	Priority    int    `yaml:"priority"` // ascending within a phase; declaration order breaks ties
}

// Op is flat and omitempty-driven on the api side; each op reads only its own
// subset of fields. The yaml keys are the frozen wire contract.
type Op struct {
	Type string `yaml:"type"`

	// header ops (request or response per the rule's Phase)
	Name  string `yaml:"name"`
	Value string `yaml:"value"`

	// redirect (request)
	To string `yaml:"to"`

	// rewrite-path (request)
	Path    string `yaml:"path"`
	Regex   string `yaml:"regex"`
	Replace string `yaml:"replace"`

	// rewrite-query (request)
	Query       map[string]string `yaml:"query"`
	RemoveQuery []string          `yaml:"remove_query"`

	// redirect / set-status
	Status int `yaml:"status"`

	// cors (response, dual-seam, sole op)
	AllowOrigins     []string `yaml:"allow_origins"`
	AllowMethods     []string `yaml:"allow_methods"`
	AllowHeaders     []string `yaml:"allow_headers"`
	ExposeHeaders    []string `yaml:"expose_headers"`
	AllowCredentials bool     `yaml:"allow_credentials"`
	MaxAge           string   `yaml:"max_age"`
}

// op type ids (the frozen vocabulary, SPEC §2.3).
const (
	opSetHeader    = "set-header"
	opRemoveHeader = "remove-header"
	opRewritePath  = "rewrite-path"
	opRewriteQuery = "rewrite-query"
	opRedirect     = "redirect"
	opSetStatus    = "set-status"
	opCORS         = "cors"
)

const (
	phaseRequest  = "request"
	phaseResponse = "response"
	modeShadow    = "shadow"
)

// Options configures filter compilation and the request snapshot resolvers,
// mirroring the ratelimit Limiter's filter knobs so a transform filter is
// bounded and resolved exactly like a WAF rule. Zero values leave the parapet
// defaults; nil Country/ASN make a geo reference (request.country/asn) simply
// never match rather than being rejected.
type Options struct {
	Country             func(*http.Request) string
	ASN                 func(*http.Request) int64
	FilterCostLimit     uint64
	FilterDisableMacros bool
}

func (o Options) predicateOptions() []waf.PredicateOption {
	var opts []waf.PredicateOption
	if o.FilterCostLimit > 0 {
		opts = append(opts, waf.WithPredicateCostLimit(o.FilterCostLimit))
	}
	if o.FilterDisableMacros {
		opts = append(opts, waf.WithPredicateDisableMacros())
	}
	return opts
}

// reqOp mutates the request in place; a true return short-circuits the chain
// (only `redirect` does this). origURI is the request URI captured BEFORE any
// rule ran, so `redirect`'s $uri token always expands to the ORIGINAL URI even
// when a higher-priority rewrite rule precedes it (SPEC open-q §12.5).
type reqOp func(w http.ResponseWriter, r *http.Request, origURI string) (shortCircuit bool)

// respOp is either a header mutation (mutate != nil) or a status override
// (setStatus > 0). The interceptor applies header mutations in order, then
// commits the last status override, so headers are never lost behind an
// early WriteHeader regardless of op declaration order.
type respOp struct {
	setStatus int
	mutate    func(http.Header)
}

type compiledReqRule struct {
	id     string
	prio   int
	filter *waf.Predicate // nil => always applies
	shadow bool
	ops    []reqOp
}

type compiledRespRule struct {
	id     string
	prio   int
	filter *waf.Predicate
	shadow bool
	ops    []respOp
}

type compiledCorsRule struct {
	id     string
	prio   int
	filter *waf.Predicate
	shadow bool
	cors   cors.CORS
}

// Zone is a compiled, immutable transform set ready for the request path. It is
// produced by Parse and swapped atomically in the controller registry; Serve
// concurrently from many requests.
type Zone struct {
	reqRules  []compiledReqRule
	respRules []compiledRespRule
	corsRules []compiledCorsRule
	country   func(*http.Request) string
	asn       func(*http.Request) int64
}

// Parse parses and compiles one or more YAML transform documents (each
// ConfigMap data value is one document) into a single Zone. Documents are
// concatenated in the caller's order; rules are split by phase and each phase
// is stable-sorted by Priority (declaration order breaks ties). Compilation is
// all-or-nothing: any YAML, validation, regex, or CEL-compile error returns a
// nil Zone and an error, so the controller keeps the previous good Zone live.
func Parse(opts Options, docs ...string) (*Zone, error) {
	var rules []Rule
	for _, doc := range docs {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var d Document
		if err := yaml.Unmarshal([]byte(doc), &d); err != nil {
			return nil, fmt.Errorf("transform: parse document: %w", err)
		}
		// A non-whitespace document that unmarshals to zero transforms is almost
		// always a wrong root key (e.g. a WAF "rules:" doc that landed in a
		// transform ConfigMap): struct unmarshal silently drops unknown keys, so
		// without this the caller would apply an empty (all-or-nothing) set and
		// advance its fingerprint, wiping the last-good Zone. Reject it so the
		// controller keeps the previous Zone. The sanctioned way to clear is
		// deleting the ConfigMap or emptying its data (a whitespace-only doc,
		// skipped above).
		if len(d.Transforms) == 0 {
			return nil, errors.New(`transform: document has no transforms (wrong root key? expected "transforms:")`)
		}
		rules = append(rules, d.Transforms...)
	}

	z := &Zone{country: opts.Country, asn: opts.ASN}
	predOpts := opts.predicateOptions()

	for _, rule := range rules {
		if err := z.compileRule(rule, predOpts); err != nil {
			return nil, fmt.Errorf("transform: rule %q: %w", rule.ID, err)
		}
	}

	// Stable sort within each phase: ascending Priority, declaration order breaks
	// ties (the slices were built in declaration order above).
	sort.SliceStable(z.reqRules, func(i, j int) bool { return z.reqRules[i].priority() < z.reqRules[j].priority() })
	sort.SliceStable(z.respRules, func(i, j int) bool { return z.respRules[i].priority() < z.respRules[j].priority() })
	sort.SliceStable(z.corsRules, func(i, j int) bool { return z.corsRules[i].priority() < z.corsRules[j].priority() })

	return z, nil
}

// priority accessors kept on the compiled rules so the sort closures read the
// stored priority without re-threading the source Rule (priorities are folded in
// during compileRule).
func (r compiledReqRule) priority() int  { return r.prio }
func (r compiledRespRule) priority() int { return r.prio }
func (r compiledCorsRule) priority() int { return r.prio }

func (z *Zone) compileRule(rule Rule, predOpts []waf.PredicateOption) error {
	var filter *waf.Predicate
	if f := strings.TrimSpace(rule.Filter); f != "" {
		p, err := waf.NewPredicate(f, predOpts...)
		if err != nil {
			return fmt.Errorf("filter: %w", err)
		}
		filter = p
	}

	switch rule.Mode {
	case "", modeShadow:
	default:
		return fmt.Errorf("invalid mode %q", rule.Mode)
	}
	shadow := rule.Mode == modeShadow

	if len(rule.Ops) == 0 {
		return errors.New("rule has no ops")
	}

	switch rule.Phase {
	case phaseRequest:
		ops, err := compileReqOps(rule.Ops)
		if err != nil {
			return err
		}
		z.reqRules = append(z.reqRules, compiledReqRule{id: rule.ID, prio: rule.Priority, filter: filter, shadow: shadow, ops: ops})
	case phaseResponse:
		// cors is the dual-seam op: a response-phase rule whose sole op is `cors`
		// is mounted as a standalone request-spanning cors.CORS middleware, NOT via
		// the response interceptor (SPEC §2.3).
		if isCORSRule(rule.Ops) {
			c, err := compileCORS(rule.Ops[0])
			if err != nil {
				return err
			}
			z.corsRules = append(z.corsRules, compiledCorsRule{id: rule.ID, prio: rule.Priority, filter: filter, shadow: shadow, cors: c})
			return nil
		}
		ops, err := compileRespOps(rule.Ops)
		if err != nil {
			return err
		}
		z.respRules = append(z.respRules, compiledRespRule{id: rule.ID, prio: rule.Priority, filter: filter, shadow: shadow, ops: ops})
	default:
		return fmt.Errorf("invalid phase %q", rule.Phase)
	}
	return nil
}

func isCORSRule(ops []Op) bool {
	return len(ops) == 1 && ops[0].Type == opCORS
}

func compileReqOps(ops []Op) ([]reqOp, error) {
	out := make([]reqOp, 0, len(ops))
	for i, op := range ops {
		switch op.Type {
		case opSetHeader:
			if err := validateHeaderNameValue(op.Name, op.Value); err != nil {
				return nil, fmt.Errorf("set-header: %w", err)
			}
			name, value := op.Name, op.Value
			out = append(out, func(_ http.ResponseWriter, r *http.Request, _ string) bool {
				r.Header.Set(name, value)
				return false
			})
		case opRemoveHeader:
			if err := validateHeaderName(op.Name); err != nil {
				return nil, fmt.Errorf("remove-header: %w", err)
			}
			name := op.Name
			out = append(out, func(_ http.ResponseWriter, r *http.Request, _ string) bool {
				r.Header.Del(name)
				return false
			})
		case opRewritePath:
			rw, err := compileRewritePath(op)
			if err != nil {
				return nil, err
			}
			out = append(out, rw)
		case opRewriteQuery:
			rw, err := compileRewriteQuery(op)
			if err != nil {
				return nil, err
			}
			out = append(out, rw)
		case opRedirect:
			// redirect short-circuits the whole chain, so any later op would be
			// dead code: it must be the sole op in its rule (SPEC §3.4).
			if len(ops) != 1 {
				return nil, errors.New("redirect must be the only op in its rule")
			}
			to := op.To
			status := op.Status
			if status == 0 {
				status = http.StatusFound // 302 default
			}
			out = append(out, func(w http.ResponseWriter, r *http.Request, origURI string) bool {
				target := strings.ReplaceAll(to, "$uri", origURI)
				http.Redirect(w, r, target, status)
				return true
			})
		default:
			return nil, fmt.Errorf("op %d: %q is not a request-phase op", i, op.Type)
		}
	}
	return out, nil
}

func compileRewritePath(op Op) (reqOp, error) {
	// literal `path` XOR (`regex` + `replace`).
	if op.Path != "" {
		if op.Regex != "" || op.Replace != "" {
			return nil, errors.New("rewrite-path: set exactly one of path or regex+replace")
		}
		path := op.Path
		return func(_ http.ResponseWriter, r *http.Request, _ string) bool {
			r.URL.Path = path
			r.URL.RawPath = "" // recompute the escaped form from Path
			return false
		}, nil
	}
	if op.Regex == "" || op.Replace == "" {
		return nil, errors.New("rewrite-path: requires path, or regex+replace")
	}
	re, err := regexp.Compile(op.Regex)
	if err != nil {
		return nil, fmt.Errorf("rewrite-path: regex: %w", err)
	}
	replace := op.Replace
	return func(_ http.ResponseWriter, r *http.Request, _ string) bool {
		r.URL.Path = re.ReplaceAllString(r.URL.Path, replace)
		r.URL.RawPath = ""
		return false
	}, nil
}

func compileRewriteQuery(op Op) (reqOp, error) {
	if len(op.Query) == 0 && len(op.RemoveQuery) == 0 {
		return nil, errors.New("rewrite-query: requires query and/or remove_query")
	}
	setQuery := op.Query
	removeQuery := op.RemoveQuery
	return func(_ http.ResponseWriter, r *http.Request, _ string) bool {
		q := r.URL.Query()
		for k, v := range setQuery {
			q.Set(k, v)
		}
		for _, k := range removeQuery {
			q.Del(k)
		}
		r.URL.RawQuery = q.Encode()
		return false
	}, nil
}

// validateHeaderName rejects a header-name op.Name that would misbehave at
// emit time (net/http silently drops an invalid Set/Del token), so the
// all-or-nothing compile catches a typo instead of shipping garbage.
func validateHeaderName(name string) error {
	if !httpguts.ValidHeaderFieldName(name) {
		return fmt.Errorf("invalid header name %q", name)
	}
	return nil
}

// validateHeaderNameValue additionally rejects a header value carrying
// disallowed bytes (e.g. a bare CR/LF), same rationale as validateHeaderName.
func validateHeaderNameValue(name, value string) error {
	if err := validateHeaderName(name); err != nil {
		return err
	}
	if !httpguts.ValidHeaderFieldValue(value) {
		return fmt.Errorf("invalid header value for %q", name)
	}
	return nil
}

func compileRespOps(ops []Op) ([]respOp, error) {
	out := make([]respOp, 0, len(ops))
	for i, op := range ops {
		switch op.Type {
		case opSetHeader:
			if err := validateHeaderNameValue(op.Name, op.Value); err != nil {
				return nil, fmt.Errorf("set-header: %w", err)
			}
			name, value := op.Name, op.Value
			out = append(out, respOp{mutate: func(h http.Header) { h.Set(name, value) }})
		case opRemoveHeader:
			if err := validateHeaderName(op.Name); err != nil {
				return nil, fmt.Errorf("remove-header: %w", err)
			}
			name := op.Name
			out = append(out, respOp{mutate: func(h http.Header) { h.Del(name) }})
		case opSetStatus:
			if op.Status < 100 || op.Status > 599 {
				return nil, fmt.Errorf("set-status: status %d out of range", op.Status)
			}
			out = append(out, respOp{setStatus: op.Status})
		case opCORS:
			// cors must be the sole op in its rule and is routed to the standalone
			// mount in compileRule; reaching here means it was mixed with other ops.
			return nil, errors.New("cors must be the only op in its rule")
		default:
			return nil, fmt.Errorf("op %d: %q is not a response-phase op", i, op.Type)
		}
	}
	return out, nil
}

func compileCORS(op Op) (cors.CORS, error) {
	c := cors.CORS{
		AllowMethods:     op.AllowMethods,
		AllowHeaders:     op.AllowHeaders,
		ExposeHeaders:    op.ExposeHeaders,
		AllowCredentials: op.AllowCredentials,
	}
	if op.MaxAge != "" {
		d, err := time.ParseDuration(op.MaxAge)
		if err != nil {
			return cors.CORS{}, fmt.Errorf("cors: max_age: %w", err)
		}
		c.MaxAge = d
	}
	if len(op.AllowOrigins) == 0 {
		return cors.CORS{}, errors.New("cors: allow_origins is required")
	}
	// A single "*" origin means "any origin". Browsers forbid wildcard-with-
	// credentials, which cors.CORS.ServeHandler would PANIC on — refuse it here so
	// a bad set is rejected all-or-nothing instead of crashing the request path.
	if len(op.AllowOrigins) == 1 && op.AllowOrigins[0] == "*" {
		if op.AllowCredentials {
			return cors.CORS{}, errors.New("cors: allow_credentials cannot be combined with a wildcard origin")
		}
		c.AllowAllOrigins = true
	} else {
		c.AllowOrigins = cors.AllowOrigins(op.AllowOrigins...)
	}
	return c, nil
}

// ServeHandler wraps next with the zone's request- and response-phase mutations
// (plus the cors special-case mount). It is the parapet.Middleware seam the
// per-Ingress TransformZone plugin mounts.
func (z *Zone) ServeHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture the URI before any rule mutates the request, so `redirect`'s
		// $uri expands to the original (SPEC open-q §12.5).
		origURI := r.URL.RequestURI()

		// The CEL request snapshot is built lazily and rebuilt whenever a request
		// rule mutates the request, so each rule's predicate (and every response/
		// cors predicate) sees the request as mutated by all prior request rules
		// (SPEC §4.2 — request rules compose top-to-bottom).
		var (
			input      waf.Input
			inputValid bool
		)
		evalInput := func() waf.Input {
			if !inputValid {
				var country string
				var asn int64
				if z.country != nil {
					country = z.country(r)
				}
				if z.asn != nil {
					asn = z.asn(r)
				}
				input = waf.NewInput(r, "", country, asn)
				inputValid = true
			}
			return input
		}
		// matched reports whether a rule's filter fires. A nil filter always
		// matches; a runtime EVAL error skips the rule (no mutation) — fail-closed
		// for a mutation layer.
		matched := func(filter *waf.Predicate) bool {
			if filter == nil {
				return true
			}
			ok, err := filter.Eval(r.Context(), evalInput())
			if err != nil {
				return false
			}
			return ok
		}

		// Request phase: apply ops in priority order; a redirect short-circuits.
		for i := range z.reqRules {
			rule := &z.reqRules[i]
			if !matched(rule.filter) {
				continue
			}
			if rule.shadow {
				continue // count the match (Phase-2 metric); apply no mutation
			}
			for _, op := range rule.ops {
				if op(w, r, origURI) {
					return
				}
			}
			inputValid = false // request mutated; later predicates see a fresh snapshot
		}

		// Response phase: collect matched ops for one interceptor.
		var respOps []respOp
		for i := range z.respRules {
			rule := &z.respRules[i]
			if !matched(rule.filter) {
				continue
			}
			if rule.shadow {
				continue
			}
			respOps = append(respOps, rule.ops...)
		}

		h := next
		if len(respOps) > 0 {
			h = headers.InterceptResponse(func(rw headers.ResponseHeaderWriter) {
				status := 0
				for _, op := range respOps {
					if op.setStatus > 0 {
						status = op.setStatus
						continue
					}
					op.mutate(rw.Header())
				}
				if status > 0 {
					rw.WriteHeader(status)
				}
			}).ServeHandler(h)
		}

		// cors special-case: each matched cors rule wraps the chain as a standalone
		// request-spanning middleware (handles its own OPTIONS preflight). Wrapped
		// in reverse so the lowest-priority rule ends up outermost.
		for i := len(z.corsRules) - 1; i >= 0; i-- {
			rule := &z.corsRules[i]
			if !matched(rule.filter) {
				continue
			}
			if rule.shadow {
				continue
			}
			h = rule.cors.ServeHandler(h)
		}

		h.ServeHTTP(w, r)
	})
}

// IDs returns every compiled rule id (request, then response, then cors), in
// evaluation order. Used for introspection and reload logging, mirroring
// ratelimitrule.Limiter.IDs.
func (z *Zone) IDs() []string {
	out := make([]string, 0, len(z.reqRules)+len(z.respRules)+len(z.corsRules))
	for i := range z.reqRules {
		out = append(out, z.reqRules[i].id)
	}
	for i := range z.respRules {
		out = append(out, z.respRules[i].id)
	}
	for i := range z.corsRules {
		out = append(out, z.corsRules[i].id)
	}
	return out
}

// Empty reports whether the zone has no rules (a valid inert zone, e.g. from a
// ConfigMap whose data values are all whitespace — a non-whitespace document
// that yields zero transforms is rejected by Parse). The plugin still mounts it
// as a cheap pass-through.
func (z *Zone) Empty() bool {
	return len(z.reqRules) == 0 && len(z.respRules) == 0 && len(z.corsRules) == 0
}
