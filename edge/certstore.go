// Package edge implements the out-of-cluster parapet edge proxy in Go (built on
// the parapet middleware framework), the counterpart to the in-cluster edge
// control plane (go/edgecp). It terminates public TLS locally with a cert+key
// fetched from the control plane, runs the global + zone WAF as an early-drop
// layer, optionally caches responses on disk, and forwards to the in-cluster
// parapet with the X-Forwarded-* headers parapet trusts. See ../EDGE.md.
//
// The edge reuses the
// controller's cert.Table (SNI resolution), wafrule + parapet/pkg/waf (the
// CEL engine), and geoip packages verbatim, so the edge WAF blocks identically
// to parapet — which remains authoritative and re-runs the full WAF.
package edge

import (
	"crypto/tls"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/moonrhythm/parapet-ingress-controller/cert"
)

// On-demand (serve-all) fetch guards. A handshake for an unheld SNI blocks on a
// synchronous control-plane round-trip, so an unguarded path lets a flood of
// missing/denied SNIs tie up handshake goroutines and hammer the CP (each 404 is
// re-fetched on every handshake). These defaults bound all three blast radii;
// override via ConfigureOnDemand.
const (
	defaultOnDemandNegTTL      = 30 * time.Second // how long a missed SNI is suppressed
	defaultOnDemandMaxInFlight = 32               // global cap on concurrent on-demand fetches
	maxNegCacheEntries         = 4096             // bound the negative cache's own memory
)

// CertStore is the edge's in-memory, hot-swappable certificate store. It holds
// the cert+key for each domain the edge serves, indexed for SNI lookup by
// reusing the controller's cert.Table (so exact + single-label-wildcard
// resolution behaves exactly like parapet). Keys live only here — never written
// to disk. See EDGE.md "Cert distribution flow".
//
// Two-part structure:
//   - table: the lock-free SNI index read on every TLS handshake.
//   - cache: source of truth keyed by the *fetch key* (the domain the edge
//     requested, e.g. "acme.com" or "*.acme.com"), used to rebuild table and to
//     remember each domain's ETag for revalidation.
type CertStore struct {
	table cert.Table // lock-free read on the handshake path (its own RWMutex)

	mu     sync.Mutex
	cache  map[string]cachedCert // fetch key -> parsed cert + its ETag
	loaded atomic.Bool           // flips true after the first successful Update (readiness)

	// onDemand, when set (serve-all mode), fetches a missing SNI's cert from the
	// control plane during the handshake. nil in pinned mode (a miss falls back
	// to self-signed). Set via SetOnDemand.
	onDemand func(sni string)

	// On-demand fetch guards (serve-all only; dormant while onDemand is nil).
	//   - sf collapses concurrent handshakes for the SAME SNI into one CP fetch
	//     whose result (a populated table) every waiter then reads.
	//   - sem caps concurrent fetches across DISTINCT SNIs: over the cap a handshake
	//     self-signs immediately instead of queueing on the CP (flood shedding).
	//   - miss is a short-TTL negative cache so a missing/denied SNI isn't re-fetched
	//     on every handshake; cleared whenever Update lands a cert for the key.
	sf     singleflight.Group
	sem    chan struct{}
	negTTL time.Duration

	missMu sync.Mutex
	miss   map[string]time.Time // SNI -> suppress-until
}

type cachedCert struct {
	cert *tls.Certificate
	etag string
}

// NewCertStore returns an empty store with the on-demand guards at their defaults
// (active only once SetOnDemand wires a fetcher).
func NewCertStore() *CertStore {
	return &CertStore{
		cache:  map[string]cachedCert{},
		miss:   map[string]time.Time{},
		sem:    make(chan struct{}, defaultOnDemandMaxInFlight),
		negTTL: defaultOnDemandNegTTL,
	}
}

// ConfigureOnDemand tunes the serve-all on-demand fetch guards. negTTL is how long a
// missing/denied SNI is suppressed from re-fetching; maxInFlight caps concurrent
// on-demand fetches (excess handshakes self-sign immediately rather than queueing on
// the control plane). Non-positive values keep the current setting. Call once at
// startup, before serving.
func (s *CertStore) ConfigureOnDemand(negTTL time.Duration, maxInFlight int) {
	if negTTL > 0 {
		s.negTTL = negTTL
	}
	if maxInFlight > 0 {
		s.sem = make(chan struct{}, maxInFlight)
	}
}

// SetOnDemand enables serve-all mode: a handshake for an SNI not in the store
// triggers fetch(sni) (a blocking control-plane fetch) before falling back to
// the self-signed cert. fetch must be safe for concurrent use.
func (s *CertStore) SetOnDemand(fetch func(sni string)) {
	s.onDemand = fetch
}

// GetCertificate is the tls.Config.GetCertificate callback. It resolves the SNI
// against the live table; on a miss in serve-all mode it fetches the cert on
// demand (the handshake blocks on it) and retries. Returns (nil, nil) on a final
// miss so crypto/tls falls back to tls.Config.Certificates[0] (the self-signed
// fallback) — it never errors the handshake.
func (s *CertStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c, _ := s.table.Get(hello); c != nil {
		return c, nil
	}
	if s.onDemand != nil && hello.ServerName != "" {
		// Normalize identically to cert.Table.Get and the control plane's authz/store
		// (RFC 6066 forbids a trailing dot, but non-compliant clients send one) so the
		// fetch key, negative cache, and CP authorization all agree on the same SNI —
		// otherwise "example.com." and "example.com" fetch (and negative-cache) as two
		// distinct domains, causing repeated on-demand churn.
		sni := normalizeSNI(hello.ServerName)
		if sni != "" {
			s.fetchOnDemand(sni)
			if c, _ := s.table.Get(hello); c != nil {
				return c, nil
			}
		}
	}
	return nil, nil // -> self-signed fallback (client sees "unknown authority")
}

// normalizeSNI lowercases and trims a trailing dot, matching cert.Table.Get and
// edgecp's CertStore.Get/Authz.Allowed so lookup, fetch key, and CP authz agree.
func normalizeSNI(sni string) string {
	return strings.ToLower(strings.TrimSuffix(sni, "."))
}

// fetchOnDemand resolves a missing SNI through the control plane under three guards:
// a negative cache (recently-missed SNIs short-circuit without a CP call), single-flight
// (concurrent handshakes for the same SNI share one fetch), and a global in-flight cap
// (excess distinct-SNI fetches shed to self-signed). On success the cert lands in the
// table; GetCertificate re-reads it.
func (s *CertStore) fetchOnDemand(sni string) {
	if s.suppressed(sni) {
		ondemand("suppressed")
		return
	}
	// Single-flight: the leader fetches; followers for the same SNI block on it and then
	// read the populated table. The leader's result is dropped once it returns, so a later
	// handshake re-evaluates (gated by the negative cache).
	_, _, _ = s.sf.Do(sni, func() (any, error) {
		// Global cap: a flood of DISTINCT missing SNIs sheds here rather than queueing a
		// blocking CP round-trip per handshake. Same-SNI load is already collapsed above,
		// so one slot covers a herd.
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		default:
			ondemand("shed")
			return nil, nil
		}
		s.onDemand(sni)
		if s.cached(sni) {
			s.clearMiss(sni)
			ondemand("hit")
		} else {
			s.recordMiss(sni)
			ondemand("miss")
		}
		return nil, nil
	})
}

// suppressed reports whether sni is within its negative-cache window, evicting the
// entry lazily on expiry.
func (s *CertStore) suppressed(sni string) bool {
	s.missMu.Lock()
	defer s.missMu.Unlock()
	until, ok := s.miss[sni]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(s.miss, sni)
		return false
	}
	return true
}

// recordMiss negative-caches sni for negTTL. It is self-bounding: at the cap it first
// sweeps expired entries, then drops the record rather than growing unboundedly (the
// in-flight cap still bounds CP load, so a dropped record only forgoes the optimization).
func (s *CertStore) recordMiss(sni string) {
	s.missMu.Lock()
	defer s.missMu.Unlock()
	if len(s.miss) >= maxNegCacheEntries {
		now := time.Now()
		for k, until := range s.miss {
			if now.After(until) {
				delete(s.miss, k)
			}
		}
		if len(s.miss) >= maxNegCacheEntries {
			return
		}
	}
	s.miss[sni] = time.Now().Add(s.negTTL)
}

// clearMiss drops any negative-cache entry for key (a cert is now available).
func (s *CertStore) clearMiss(key string) {
	s.missMu.Lock()
	defer s.missMu.Unlock()
	delete(s.miss, key)
}

// cached reports whether a cert is currently stored under fetch key.
func (s *CertStore) cached(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.cache[key]
	return ok
}

// Update installs/replaces the material for a fetch key and atomically rebuilds
// the SNI index. Returns false if the PEM can't be parsed into a key pair — the
// caller keeps the old copy (fail-static); the old cert + old ETag are retained.
func (s *CertStore) Update(key string, chainPEM, keyPEM []byte, etag string) bool {
	crt, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return false
	}

	s.mu.Lock()
	s.cache[key] = cachedCert{cert: &crt, etag: etag}
	certs := make([]*tls.Certificate, 0, len(s.cache))
	for _, c := range s.cache {
		certs = append(certs, c.cert)
	}
	s.mu.Unlock()

	// Rebuild the SAN index from every cached cert and swap it in atomically.
	s.table.Set(certs)
	s.loaded.Store(true)
	s.clearMiss(key) // a cert now exists for this key — lift any negative-cache suppression
	return true
}

// Etag returns the ETag currently cached for a fetch key (sent as If-None-Match),
// or "" if none.
func (s *CertStore) Etag(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cache[key].etag
}

// Keys returns the fetch keys currently cached. The periodic refresh uses this
// to keep on-demand-fetched domains (serve-all mode) rotated, not just a fixed
// list.
func (s *CertStore) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.cache))
	for k := range s.cache {
		out = append(out, k)
	}
	return out
}

// Len is the number of domains currently cached (for logging).
func (s *CertStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.cache)
}

// Loaded reports whether at least one cert has been successfully loaded (used by
// the readiness probe).
func (s *CertStore) Loaded() bool {
	return s.loaded.Load()
}
