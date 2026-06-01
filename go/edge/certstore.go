// Package edge implements the out-of-cluster parapet edge proxy in Go (built on
// the parapet middleware framework), the counterpart to the in-cluster edge
// control plane (go/edgecp). It terminates public TLS locally with a cert+key
// fetched from the control plane, runs the global + zone WAF as an early-drop
// layer, optionally caches responses on disk, and forwards to the in-cluster
// parapet with the X-Forwarded-* headers parapet trusts. See ../../EDGE.md.
//
// This replaces the former Rust/Pingora edge (rust/edge): same HTTP/JSON control
// -plane contract, same env contract, same per-request behavior. It reuses the
// Go controller's cert.Table (SNI resolution), wafrule + parapet/pkg/waf (the
// CEL engine), and geoip packages verbatim, so the edge WAF blocks identically
// to parapet — which remains authoritative and re-runs the full WAF.
package edge

import (
	"crypto/tls"
	"sync"
	"sync/atomic"

	"github.com/moonrhythm/parapet-ingress-controller/go/cert"
)

// CertStore is the edge's in-memory, hot-swappable certificate store. It holds
// the cert+key for each domain the edge serves, indexed for SNI lookup by
// reusing the controller's cert.Table (so exact + single-label-wildcard
// resolution behaves exactly like parapet). Keys live only here — never written
// to disk. See EDGE.md "Cert distribution flow".
//
// Two-part structure mirrors the Rust edge's CertStore:
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
}

type cachedCert struct {
	cert *tls.Certificate
	etag string
}

// NewCertStore returns an empty store.
func NewCertStore() *CertStore {
	return &CertStore{cache: map[string]cachedCert{}}
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
// fallback) — it never errors the handshake, matching the Rust edge.
func (s *CertStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c, _ := s.table.Get(hello); c != nil {
		return c, nil
	}
	if s.onDemand != nil && hello.ServerName != "" {
		s.onDemand(hello.ServerName)
		if c, _ := s.table.Get(hello); c != nil {
			return c, nil
		}
	}
	return nil, nil // -> self-signed fallback (client sees "unknown authority")
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
