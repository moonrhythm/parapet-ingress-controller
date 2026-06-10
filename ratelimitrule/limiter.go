package ratelimitrule

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/moonrhythm/parapet/pkg/header"
	"github.com/moonrhythm/parapet/pkg/ratelimit"
)

const (
	defaultStatus  = http.StatusTooManyRequests
	defaultMessage = "Too Many Requests"

	// minWindow..maxWindow bound the per-key map retention. maxWindow matches
	// the worst pre-existing opt-in exposure (the per-hour annotation limiter):
	// a longer window would hold every distinct key seen for its whole span.
	minWindow = time.Second
	maxWindow = time.Hour

	maxIDLen = 63

	// acmeChallengePrefix is never rate limited — platform-injected middleware
	// must not break certificate issuance (same invariant as RedirectHTTPS and
	// AllowRemote), and ACME validation probes come from unpublished IPs that an
	// ip-keyed limit could 429 fleet-wide.
	acmeChallengePrefix = "/.well-known/acme-challenge"

	// collapsedHost is the shared bucket key for host-keyed limits when the
	// router doesn't serve the request's Host (KnownHost is wired): a
	// random-Host flood mints one bucket, not unbounded ones. The global set
	// sees such requests on every flood; a zone set sees them when it is bound
	// to an ingress with host-less (catch-all) rules, which route any Host.
	collapsedHost = "other"
)

// ipv6Mask aggregates IPv6 keys per /64: one eyeball network is one bucket, so
// a single /64 can't mint 2^64 distinct keys against an ip-keyed limit.
var ipv6Mask = net.CIDRMask(64, 128)

// maxKeyPartLen caps a header/cookie value's contribution to the bucket key.
// Values past the cap share a bucket with their 128-byte prefix — conservative
// (never relaxes a limit) — and a client can't inflate per-entry memory with
// megabyte header values. Entry COUNT for these client-controlled
// characteristics is still unbounded within the window retention; see the
// cardinality warning in RATELIMIT.md.
const maxKeyPartLen = 128

// keyKind is one bucket characteristic. A limit's bucket key is the
// "\n"-joined composition of its parts' per-request values. The composition is
// injective for reachable inputs — but NOT because no part can contain a
// newline: raw IP bytes can (any octet 0x0A, e.g. 10.x.x.x). It holds because
// every OTHER part value is newline-free (Go's server rejects control bytes in
// Host/header/cookie values; ASN/country are formatted), a limit's part list
// is fixed, and duplicate parts are rejected — so the newline-free parts
// anchor unambiguous boundaries around the at-most-variable IP part. Even a
// hypothetical collision would only share a bucket (a stricter limit), never
// cross a security boundary. Re-derive this argument before adding a part
// kind whose value can carry raw bytes.
type keyKind uint8

const (
	keyIP keyKind = iota
	keyHost
	keyASN
	keyCountry
	keyHeader
	keyCookie
)

// keyPart is one compiled characteristic; name carries the header/cookie name.
type keyPart struct {
	kind keyKind
	name string
}

type mode uint8

const (
	modeEnforce mode = iota
	modeShadow
)

// compiledLimit is one limit ready for the request path: enums resolved,
// strategy built, observe handles pre-resolved. Immutable after the set is
// published.
type compiledLimit struct {
	id       string
	keyParts []keyPart
	strategy ratelimit.Strategy
	mode     mode
	status   int
	message  string
	exclude  []*net.IPNet
	observe  ratelimit.ObserveFunc // nil when no Observe factory is wired

	// cfgKey fingerprints the strategy-shaping config (key|algorithm|rate|window).
	// SetLimits carries the old strategy forward when it is unchanged, so editing
	// a limit's message — or a sibling limit — never resets live counters.
	cfgKey string
}

// set is one immutable compiled batch, swapped atomically into the Limiter.
// The request path loads the pointer exactly once per request and evaluates
// that whole set, so a mid-request swap can't mix old and new limits.
type set struct {
	limits      []compiledLimit
	source      []Limit // normalized input, for introspection
	needsIP     bool    // any limit keys on ip or carries an exclude list
	needsCookie bool    // any limit keys on a cookie
	knownHost   func(host string) bool
	country     func(*http.Request) string // nil only when no limit keys on country
	asn         func(*http.Request) int64  // nil only when no limit keys on asn
}

// Limiter is a hot-swappable set of rate limits — the runtime for both the
// global instance and each zone. Configure the exported fields before the
// first SetLimits; they are read at compile time, not per request.
//
// An empty Limiter (no SetLimits yet, or an empty batch) passes every request
// through.
type Limiter struct {
	set atomic.Pointer[set]
	mu  sync.Mutex // serializes SetLimits (validate+compile+swap)

	// NamePrefix scopes the metric name of every limit in this set:
	// parapet_ratelimit_total{name="<NamePrefix>:<id>"}. The controller uses
	// "global" and "zone:<ns>/<name>" — both disjoint from the annotation
	// limiters' "<ns>/<ingress>:<s|m|h>" names, so series can't merge.
	NamePrefix string

	// Observe builds the per-limit decision observer (e.g.
	// metric/observe.RateLimit). Resolved once per limit at SetLimits, so the
	// request path is lookup-free. nil disables decision metrics.
	Observe func(name string) ratelimit.ObserveFunc

	// KnownHost, when set, collapses host bucket keys the router doesn't serve
	// into one shared bucket (see collapsedHost). The controller wires it on the
	// global instance and on every zone: zone traffic usually carries a served
	// Host, but an ingress with host-less (catch-all) rules routes ANY Host into
	// its zone, so an unwired zone would be unbounded-key mintable.
	KnownHost func(host string) bool

	// Country resolves the client's ISO country for `country` keys (the same
	// GeoIP resolver the WAF uses for request.country). nil makes SetLimits
	// reject country-keyed limits: without a resolver every client would share
	// one bucket, silently turning the limit into an aggregate cap.
	Country func(*http.Request) string

	// ASN resolves the client's autonomous system number for `asn` keys (the
	// WAF's request.asn resolver). nil makes SetLimits reject asn-keyed limits,
	// for the same reason as Country.
	ASN func(*http.Request) int64
}

// Limits returns the normalized limits of the live set (defaults resolved), in
// declaration order. Nil when nothing is loaded.
func (l *Limiter) Limits() []Limit {
	s := l.set.Load()
	if s == nil {
		return nil
	}
	return s.source
}

// IDs returns the live set's limit ids in declaration order, for logs/tests.
func (l *Limiter) IDs() []string {
	s := l.set.Load()
	if s == nil {
		return nil
	}
	ids := make([]string, len(s.limits))
	for i := range s.limits {
		ids[i] = s.limits[i].id
	}
	return ids
}

// SetLimits validates and compiles the batch, then atomically swaps it in.
// All-or-nothing: any invalid limit rejects the whole batch and the previous
// good set stays live, so a bad ConfigMap edit can't drop enforcement.
// Strategies whose shaping config (key, algorithm, rate, window) is unchanged
// are carried over from the live set with their counters intact.
func (l *Limiter) SetLimits(limits []Limit) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var errs []error
	seen := make(map[string]struct{}, len(limits))
	compiled := make([]compiledLimit, 0, len(limits))
	source := make([]Limit, 0, len(limits))

	for i, lim := range limits {
		c, norm, err := l.compileLimit(lim)
		if err != nil {
			errs = append(errs, fmt.Errorf("ratelimit: limit[%d] %q: %w", i, lim.ID, err))
			continue
		}
		if _, dup := seen[c.id]; dup {
			errs = append(errs, fmt.Errorf("ratelimit: limit[%d] %q: duplicate id", i, lim.ID))
			continue
		}
		seen[c.id] = struct{}{}
		compiled = append(compiled, c)
		source = append(source, norm)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}

	// Carry live counters across the swap for limits whose strategy-shaping
	// config didn't change (the strategy is keyed by id; an id rename is a
	// legitimate reset).
	if cur := l.set.Load(); cur != nil {
		old := make(map[string]*compiledLimit, len(cur.limits))
		for i := range cur.limits {
			old[cur.limits[i].id] = &cur.limits[i]
		}
		for i := range compiled {
			if o, ok := old[compiled[i].id]; ok && o.cfgKey == compiled[i].cfgKey {
				compiled[i].strategy = o.strategy
			}
		}
	}

	s := &set{
		limits:    compiled,
		source:    source,
		knownHost: l.KnownHost,
		country:   l.Country,
		asn:       l.ASN,
	}
	for i := range compiled {
		// The exclude clause matters on its own: a limit without an ip part
		// still needs the client IP resolved for its exclude list, or it would
		// silently never match (skip sees a nil IP).
		if len(compiled[i].exclude) > 0 {
			s.needsIP = true
		}
		for _, p := range compiled[i].keyParts {
			switch p.kind {
			case keyIP:
				s.needsIP = true
			case keyCookie:
				s.needsCookie = true
			}
		}
	}
	l.set.Store(s)
	return nil
}

// compileLimit validates one limit and builds its compiled form plus the
// normalized (defaults-resolved) source copy.
func (l *Limiter) compileLimit(lim Limit) (compiledLimit, Limit, error) {
	var errs []error

	if err := validateID(lim.ID); err != nil {
		errs = append(errs, err)
	}

	parts, normKeys, keyErrs := l.compileKeys(lim.Key)
	errs = append(errs, keyErrs...)
	lim.Key = normKeys

	if lim.Rate <= 0 {
		errs = append(errs, fmt.Errorf("rate must be > 0 (got %d)", lim.Rate))
	}

	var window time.Duration
	if strings.TrimSpace(lim.Window) == "" {
		errs = append(errs, errors.New("window is required"))
	} else if d, err := time.ParseDuration(lim.Window); err != nil {
		errs = append(errs, fmt.Errorf("invalid window: %w", err))
	} else if d < minWindow || d > maxWindow {
		errs = append(errs, fmt.Errorf("window %s out of bounds (want %s..%s)", d, minWindow, maxWindow))
	} else {
		window = d
		lim.Window = d.String()
	}

	switch lim.Algorithm {
	case "", "fixed":
		lim.Algorithm = "fixed"
	case "sliding":
	default:
		errs = append(errs, fmt.Errorf("unknown algorithm %q (want fixed|sliding)", lim.Algorithm))
	}

	var m mode
	switch lim.Mode {
	case "", "enforce":
		m, lim.Mode = modeEnforce, "enforce"
	case "shadow":
		m = modeShadow
	default:
		errs = append(errs, fmt.Errorf("unknown mode %q (want enforce|shadow)", lim.Mode))
	}

	switch lim.Status {
	case 0, http.StatusTooManyRequests:
		lim.Status = defaultStatus
	case http.StatusServiceUnavailable:
	default:
		// Keeps the status-derived parapet_rejected_requests reason truthful: 429
		// maps to the rate-limit reason, 503 is deliberately uncounted there (it
		// cannot adopt another rejection's reason), while an arbitrary status
		// (403, 401, 413, ...) would silently adopt another rejection's label.
		errs = append(errs, fmt.Errorf("status %d not allowed (want 429 or 503)", lim.Status))
	}

	if lim.Message == "" {
		lim.Message = defaultMessage
	}

	var exclude []*net.IPNet
	for _, cidr := range lim.Exclude {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid exclude CIDR %q: %w", cidr, err))
			continue
		}
		exclude = append(exclude, ipnet)
	}

	if err := errors.Join(errs...); err != nil {
		return compiledLimit{}, Limit{}, err
	}

	c := compiledLimit{
		id:       lim.ID,
		keyParts: parts,
		mode:     m,
		status:   lim.Status,
		message:  lim.Message,
		exclude:  exclude,
		// Normalized key parts can't contain "," (header/cookie names are HTTP
		// tokens, which exclude it), so the join is unambiguous.
		cfgKey: strings.Join(lim.Key, ",") + "|" + lim.Algorithm + "|" + strconv.Itoa(lim.Rate) + "|" + lim.Window,
	}
	if lim.Algorithm == "sliding" {
		c.strategy = newSlidingWindow(lim.Rate, window)
	} else {
		c.strategy = newFixedWindow(lim.Rate, window)
	}
	if l.Observe != nil {
		c.observe = l.Observe(l.NamePrefix + ":" + lim.ID)
	}
	return c, lim, nil
}

// compileKeys validates and normalizes a limit's key spec into compiled parts.
// An empty spec defaults to ["ip"]; the "ip-host" alias expands to ip + host.
// Returned normKeys is the canonical form (lowercased header names, alias
// expanded) — it feeds cfgKey, so spec spellings that mean the same thing
// carry counters over across reloads.
func (l *Limiter) compileKeys(keys Keys) (parts []keyPart, normKeys Keys, errs []error) {
	if len(keys) == 0 {
		keys = Keys{"ip"}
	}
	seen := map[string]struct{}{}
	add := func(norm string, p keyPart) {
		if _, dup := seen[norm]; dup {
			errs = append(errs, fmt.Errorf("duplicate key part %q", norm))
			return
		}
		seen[norm] = struct{}{}
		parts = append(parts, p)
		normKeys = append(normKeys, norm)
	}
	for _, k := range keys {
		name := ""
		hasName := false
		if i := strings.IndexByte(k, ':'); i >= 0 {
			k, name = k[:i], k[i+1:]
			hasName = true
		}
		// Only header/cookie take a :<name> suffix. Anything else is rejected
		// loudly: "country:US" or "host:example.com" read like filter syntax but
		// would otherwise silently compile as a plain per-country/per-host limit
		// on ALL traffic.
		if hasName {
			switch k {
			case "header", "cookie":
			default:
				errs = append(errs, fmt.Errorf("key %q does not take a :<name> suffix (got %q)", k, name))
				continue
			}
		}
		switch k {
		case "", "ip":
			// "" mirrors the pre-list schema, which accepted an explicit empty
			// key as the ip default.
			add("ip", keyPart{kind: keyIP})
		case "host":
			add("host", keyPart{kind: keyHost})
		case "ip-host":
			add("ip", keyPart{kind: keyIP})
			add("host", keyPart{kind: keyHost})
		case "asn":
			if l.ASN == nil {
				errs = append(errs, errors.New("key asn requires the ASN database (WAF_ASN_DB) — without it every client would share one bucket"))
				continue
			}
			add("asn", keyPart{kind: keyASN})
		case "country":
			if l.Country == nil {
				errs = append(errs, errors.New("key country requires the GeoIP database (WAF_GEOIP_DB) — without it every client would share one bucket"))
				continue
			}
			add("country", keyPart{kind: keyCountry})
		case "header":
			if err := validateFieldName(name); err != nil {
				errs = append(errs, fmt.Errorf("key header: %w", err))
				continue
			}
			// Header names are case-insensitive: normalize to lowercase so two
			// spellings share a cfgKey (and counters across reloads).
			add("header:"+strings.ToLower(name), keyPart{kind: keyHeader, name: name})
		case "cookie":
			if err := validateFieldName(name); err != nil {
				errs = append(errs, fmt.Errorf("key cookie: %w", err))
				continue
			}
			// Cookie names are case-sensitive (http.Request.Cookie matches
			// exactly); keep the given spelling.
			add("cookie:"+name, keyPart{kind: keyCookie, name: name})
		default:
			errs = append(errs, fmt.Errorf("unknown key %q (want ip|host|asn|country|header:<name>|cookie:<name>)", k))
		}
	}
	return parts, normKeys, errs
}

// validateFieldName checks a header/cookie name: non-empty and an HTTP token
// (RFC 7230) — which also guarantees it can't contain "," (the cfgKey join)
// or whitespace/control characters.
func validateFieldName(name string) error {
	if name == "" {
		return errors.New("missing name (want header:<name> / cookie:<name>)")
	}
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return fmt.Errorf("invalid character %q in name %q", c, name)
		}
	}
	return nil
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
			// "<prefix>:<id>" scheme; everything else is just kept tight.
			return fmt.Errorf("id contains %q (want [A-Za-z0-9._-])", c)
		}
	}
	return nil
}

// ServeHandler implements parapet.Middleware for the static global mount.
func (l *Limiter) ServeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.Serve(w, r, h)
	})
}

// Serve evaluates the live set against r and either rejects it or passes it to
// next. It is the zone plugin's per-request entry point (no per-request
// middleware composition) and the body of ServeHandler.
func (l *Limiter) Serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	s := l.set.Load() // exactly one load per request: the whole set is consistent
	if s == nil || len(s.limits) == 0 {
		next.ServeHTTP(w, r)
		return
	}
	s.serve(w, r, next)
}

func (s *set) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if strings.HasPrefix(r.RequestURI, acmeChallengePrefix) {
		next.ServeHTTP(w, r)
		return
	}

	// The client IP is shared by every ip-keyed limit and exclude list; resolve
	// it once. rawIP keeps parapet's ClientIP fallback semantics: an unparsable
	// X-Real-IP buckets by its raw string.
	var ip net.IP
	var rawIP string
	if s.needsIP {
		rawIP = header.Get(r.Header, header.XRealIP)
		ip = net.ParseIP(rawIP)
	}
	// Cookies are parsed once per request and shared across every cookie-keyed
	// limit: http.Request.Cookie re-parses the WHOLE Cookie header (which the
	// client sizes, up to the server's header cap) on every call, so per-part
	// calls would hand clients a CPU knob multiplied by the limit count. First
	// occurrence wins, matching Request.Cookie.
	var cookies map[string]string
	if s.needsCookie {
		all := r.Cookies()
		cookies = make(map[string]string, len(all))
		for _, c := range all {
			if _, ok := cookies[c.Name]; !ok {
				cookies[c.Name] = c.Value
			}
		}
	}

	for i := range s.limits {
		lim := &s.limits[i]

		if lim.skip(ip) {
			continue
		}
		key := s.bucketKey(lim, r, ip, rawIP, cookies)
		if lim.strategy.Take(key) {
			if lim.observe != nil {
				lim.observe(ratelimit.Event{Name: "", Result: ratelimit.ResultAllowed})
			}
			continue
		}
		if lim.observe != nil {
			lim.observe(ratelimit.Event{Name: "", Result: ratelimit.ResultLimited})
		}
		if lim.mode == modeShadow {
			continue
		}
		if after := lim.strategy.After(key); after > 0 {
			// Ceil to >= 1: truncation would emit "Retry-After: 0" for sub-second
			// waits and a compliant client would retry into another denial.
			secs := int64((after + time.Second - 1) / time.Second)
			header.Set(w.Header(), header.RetryAfter, strconv.FormatInt(secs, 10))
		}
		http.Error(w, lim.message, lim.status)
		return
	}
	next.ServeHTTP(w, r)
}

// skip reports whether the client IP is excluded from this limit.
func (lim *compiledLimit) skip(ip net.IP) bool {
	if ip == nil || len(lim.exclude) == 0 {
		return false
	}
	for _, n := range lim.exclude {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// bucketKey builds the strategy key for this limit by composing its parts'
// per-request values with "\n" (see keyKind for why that is unambiguous). The
// single-part case skips the builder — it is the common shape and stays
// alloc-free for ip/host keys.
func (s *set) bucketKey(lim *compiledLimit, r *http.Request, ip net.IP, rawIP string, cookies map[string]string) string {
	if len(lim.keyParts) == 1 {
		return s.partValue(lim.keyParts[0], r, ip, rawIP, cookies)
	}
	var b strings.Builder
	for i, p := range lim.keyParts {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(s.partValue(p, r, ip, rawIP, cookies))
	}
	return b.String()
}

// partValue resolves one characteristic for this request. IPv4 buckets per
// address, IPv6 per /64 (one eyeball network can't mint unbounded keys); an
// unparsable X-Real-IP falls back to its raw string, like parapet's ClientIP.
// host collapses unknown hosts when knownHost is wired. A missing header or
// cookie contributes "" (those clients share a bucket); values are truncated
// to maxKeyPartLen.
func (s *set) partValue(p keyPart, r *http.Request, ip net.IP, rawIP string, cookies map[string]string) string {
	switch p.kind {
	case keyHost:
		return hostKey(r.Host, s.knownHost)
	case keyASN:
		return strconv.FormatInt(s.asn(r), 10)
	case keyCountry:
		return s.country(r)
	case keyHeader:
		return truncPart(r.Header.Get(p.name))
	case keyCookie:
		return truncPart(cookies[p.name])
	default: // keyIP
		return ipKey(ip, rawIP)
	}
}

// truncPart caps a client-controlled value's contribution to the bucket key.
// Over-long values share their prefix's bucket — conservative, never relaxing
// a limit.
func truncPart(v string) string {
	if len(v) > maxKeyPartLen {
		return v[:maxKeyPartLen]
	}
	return v
}

func ipKey(ip net.IP, rawIP string) string {
	if ip == nil {
		return rawIP
	}
	if v4 := ip.To4(); v4 != nil {
		return string(v4)
	}
	return string(ip.Mask(ipv6Mask))
}

func hostKey(host string, knownHost func(string) bool) string {
	if knownHost != nil && !knownHost(host) {
		return collapsedHost
	}
	return host
}
