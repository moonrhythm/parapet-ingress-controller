// Package trust lets the in-cluster core proxy pull its edge-CA trust anchor from
// the control plane over verified server-TLS, instead of watching a k8s Secret.
// The bundle is tokenless (it carries only the public CA cert + a fingerprint;
// integrity is the caller-verified server-TLS, not a token). The core trusts any
// edge leaf that chains to this CA — CA-only trust. See EDGE-AUTOTRUST.md.
package trust

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/moonrhythm/parapet-ingress-controller/metric"
)

const maxBundleBody = 4 << 20

// Bundle is the decoded trust bundle.
type Bundle struct {
	Generation uint64
	CAPEM      []byte
	CAID       string
}

type bundleBody struct {
	Generation uint64 `json:"generation"`
	CAPEM      string `json:"ca_pem"`
	CAID       string `json:"ca_id"`
}

// Client is the tokenless client to the control plane's GET /v1/trust-bundle.
//
// By default it is HTTPS with MANDATORY, non-skippable server-TLS verification: that
// is the sole integrity guarantee that justifies dropping the bearer token (a forged
// bundle would be a trust-boundary takeover). NewClient fails if the CP server CA
// can't be loaded.
//
// NewSystemRootsClient verifies the CP server cert against the system trust store
// (used when EDGE_TRUST_CP_CA is unset); NewInsecureHTTPClient is a PLAINTEXT variant
// for transports that already provide mutual auth + encryption (http:// endpoints).
// See ClassifyEndpoint.
type Client struct {
	http *http.Client
	base string
}

// EndpointMode is how the core dials EDGE_TRUST_CP_ENDPOINT, decided by ClassifyEndpoint.
type EndpointMode int

const (
	// ModeHTTPS pulls the trust bundle over verified server-TLS (the recommended
	// mode), because the bundle is tokenless and a forged ca_pem is a fleet-wide
	// trust takeover. EDGE_TRUST_CP_CA pins a single CA; if it is unset the CP cert
	// is verified against the system trust store instead (NewSystemRootsClient).
	ModeHTTPS EndpointMode = iota
	// ModeInsecureHTTP pulls the trust bundle over PLAINTEXT http://. The tokenless
	// channel then has no in-process integrity guarantee, so it is only safe on a
	// transport that already provides mutual auth + encryption (mesh/tunnel/VPC); the
	// core logs a loud warning when it is used.
	ModeInsecureHTTP
)

// ClassifyEndpoint decides how to dial endpoint by scheme: https:// ⇒ ModeHTTPS
// (verified TLS — pinned CA or system roots), http:// ⇒ ModeInsecureHTTP (plaintext;
// the caller warns). Any other scheme, or none, is an error.
func ClassifyEndpoint(endpoint string) (EndpointMode, error) {
	switch {
	case strings.HasPrefix(endpoint, "https://"):
		return ModeHTTPS, nil
	case strings.HasPrefix(endpoint, "http://"):
		return ModeInsecureHTTP, nil
	default:
		return 0, errors.New("EDGE_TRUST_CP_ENDPOINT must be http:// or https://")
	}
}

// NewInsecureHTTPClient builds a PLAINTEXT trust client (no server-TLS, no CA), used
// when EDGE_TRUST_CP_ENDPOINT is http://. It is only safe when the transport
// (mesh/tunnel/VPC) already provides mutual auth + encryption; the core logs a loud
// warning on use. The forward-only / strict-parse / fail-static guards in Manager still
// apply, but they do NOT defend against a live MITM on a plaintext channel.
func NewInsecureHTTPClient(base string) *Client {
	return &Client{
		base: base,
		http: &http.Client{Timeout: 60 * time.Second},
	}
}

// NewSystemRootsClient builds an HTTPS trust client that verifies the CP server cert
// against the host's system root store (RootCAs nil ⇒ system roots) with hostname
// verification ON — InsecureSkipVerify is never set. Used when EDGE_TRUST_CP_CA is
// unset and the CP serves a publicly/corp-trusted cert already in the trust store. It
// is WEAKER than NewClient's pin-to-one-CA (any of the system-trusted CAs could
// impersonate the CP), so a pinned EDGE_TRUST_CP_CA remains the tightest option for
// this tokenless channel.
func NewSystemRootsClient(base string) *Client {
	return &Client{
		base: base,
		http: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				// RootCAs nil ⇒ the host's system root store; verification + hostname
				// checks stay on (no InsecureSkipVerify).
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
	}
}

// NewClient builds the client. caPEM (EDGE_TRUST_CP_CA) is the CA that signs the
// CP's SERVER cert; it MUST parse into at least one cert — no system-roots fallback,
// no InsecureSkipVerify. A non-https base is the caller's job to reject.
func NewClient(base string, caPEM []byte) (*Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("EDGE_TRUST_CP_CA: no usable certificate (mandatory; no system-roots fallback)")
	}
	return &Client{
		base: base,
		http: &http.Client{
			Timeout: 60 * time.Second, // > the server-side watch ceiling (~30s)
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
			},
		},
	}, nil
}

// Fetch GETs the trust bundle. With watch=true it long-polls (?watch=1&since=<gen>):
// the CP blocks until the generation advances or its ceiling elapses (304).
// Returns unchanged=true on 304.
func (c *Client) Fetch(sinceGen uint64, watch bool) (b Bundle, unchanged bool, err error) {
	u := c.base + "/v1/trust-bundle"
	if watch {
		u += "?watch=1&since=" + strconv.FormatUint(sinceGen, 10)
	}
	resp, err := c.http.Get(u)
	if err != nil {
		return Bundle{}, false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return Bundle{}, true, nil
	case http.StatusOK:
		var body bundleBody
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxBundleBody)).Decode(&body); err != nil {
			return Bundle{}, false, fmt.Errorf("decode: %w", err)
		}
		return Bundle{Generation: body.Generation, CAPEM: []byte(body.CAPEM), CAID: body.CAID}, false, nil
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return Bundle{}, false, fmt.Errorf("control plane returned %d for /v1/trust-bundle", resp.StatusCode)
	}
}

// Manager holds the live edge-CA pool the core's :443 VerifyClientCert checks per
// request, hot-swapped from the CP bundle with strict-parse + forward-only +
// fail-static (a bad/rollback bundle keeps last-good; the live pool is never nilled
// once set).
//
// Warm-start (EnableWarmStart): the last-good {generation, ca_id, ca_pem} is persisted to
// disk after every apply, and on startup its generation is loaded as an anti-resurrection
// FLOOR — after a restart-during-outage the manager rejects any bundle older than the
// last-good generation, so a stale CP replica can't resurrect a CA the operator just
// rotated out. The cached CA is DELIBERATELY NOT loaded into clientCAs: trust stays
// CIDR-only until the first LIVE fetch supersedes the floor (persist-and-trust would
// re-trust the rotated-out CA across the restart).
type Manager struct {
	clientCAs atomic.Pointer[x509.CertPool]
	gen       atomic.Uint64
	caID      atomic.Pointer[string]

	// floor is the persisted last-good generation: a bundle below it is rejected
	// (floor_rejected) so a restart can't regress to a rotated-out CA. 0 = no floor
	// (cold start). Written once by EnableWarmStart before Run starts, then read only
	// in apply (the single Run goroutine) — no concurrent access, so no atomic needed.
	floor uint64
	// cachePath is the warm-start file; "" disables persistence. Set by EnableWarmStart.
	cachePath string
	// lastGood is the most recent applied bundle (or, before this session's first apply, the
	// loaded warm-start entry — see EnableWarmStart), rewritten to disk on EVERY successful
	// poll (incl. 304s) so the file's written_at tracks last CP CONTACT (liveness), not last
	// CA change — otherwise a stable fleet's months-old cache would always exceed MAX_STALE
	// and the floor would never load. Set before Run starts, then touched only in Run.
	lastGood *cacheEntry

	// verifyCache memoizes VerifyClientCert results (leaf fingerprint -> chains-to-pool)
	// for the current generation, so the edge fleet's repeated requests skip the
	// per-request x509 chain build. Keyed alongside verifyGen: a pool swap (rotation)
	// advances the generation and the next access starts a fresh generation's map.
	// Bounded by clear-when-full so a flood of distinct client certs can't grow it.
	verifyMu    sync.RWMutex
	verifyGen   uint64
	verifyCache map[string]bool
}

// verifyCacheCap bounds the per-generation VerifyClientCert memo; over it, the map is
// cleared wholesale (cheap, results recompute) rather than evicted per entry.
const verifyCacheCap = 4096

func NewManager() *Manager { return &Manager{} }

// ClientCAs returns the live pool (nil before the first successful load — while it is
// nil ServerTLSConfig requests no client cert at all, so the cold-start window degrades
// to CIDR-only without prompting directly-connecting browsers; see ServerTLSConfig).
func (m *Manager) ClientCAs() *x509.CertPool { return m.clientCAs.Load() }

// WaitReady blocks until the edge-CA pool is loaded (the first successful bundle apply)
// or until timeout elapses / ctx is cancelled, whichever comes first, and reports whether
// the pool is loaded. It NEVER blocks longer than timeout: the trust CP is an optional
// overlay, so a caller gating readiness on it stays fail-static — it serves CIDR-only on a
// false return rather than coupling availability to the CP. timeout <= 0 returns the
// current state immediately. Intended as a one-shot startup gate (firstReload) so the
// edge's first connections aren't established during the cold-start window, when no
// CertificateRequest is sent and a mTLS-only edge would stay CIDR-only until the
// connection recycles. Polls (no apply-time signalling needed for a one-shot startup wait).
func (m *Manager) WaitReady(ctx context.Context, timeout time.Duration) bool {
	if m.clientCAs.Load() != nil || timeout <= 0 {
		return m.clientCAs.Load() != nil
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return m.clientCAs.Load() != nil
		case <-t.C:
			if m.clientCAs.Load() != nil {
				return true
			}
		}
	}
}

// WarmStartFloor returns the persisted last-good generation loaded as the
// anti-resurrection floor (0 = none). Read-only, for observability/tests.
func (m *Manager) WarmStartFloor() uint64 { return m.floor }

// cacheEntry is the on-disk warm-start record. ca_pem + ca_id are public (no
// secret-at-rest concern); written_at bounds staleness.
type cacheEntry struct {
	Generation uint64 `json:"generation"`
	CAID       string `json:"ca_id"`
	CAPEM      string `json:"ca_pem"`
	WrittenAt  int64  `json:"written_at"` // unix seconds
}

// EnableWarmStart wires the on-disk warm-start cache. Call ONCE before Run. It records the
// cache path (Run rewrites it after every successful apply) and, if a cache exists and is
// within maxStale, loads its generation as the anti-resurrection FLOOR: after a restart the
// manager rejects any bundle older than the last-good generation, so a stale CP replica
// can't resurrect a CA the operator just rotated out. It deliberately does NOT load the
// cached CA into ClientCAs — trust stays CIDR-only until the first LIVE fetch supersedes the
// floor. A missing / corrupt / too-stale / zero-generation cache is a quiet no-op
// (cold-start, no floor). maxStale<=0 disables the age bound.
func (m *Manager) EnableWarmStart(path string, maxStale time.Duration) {
	m.cachePath = path
	if path == "" {
		return
	}
	e, err := readCache(path)
	if err != nil {
		if !os.IsNotExist(err) {
			// A corrupt/unreadable cache is non-fatal: cold-start with no floor (safe — we
			// just lose the cross-restart anti-resurrection guard until the next apply).
			slog.Warn("core: warm-start cache unreadable; cold-starting with no floor", "path", path, "error", err)
		}
		return
	}
	if maxStale > 0 {
		if age := time.Since(time.Unix(e.WrittenAt, 0)); age > maxStale {
			slog.Warn("core: warm-start cache too stale; discarding (cold-start, no floor)",
				"path", path, "age", age.Round(time.Second), "max_stale", maxStale)
			return
		}
	}
	m.floor = e.Generation
	// Seed lastGood from the cache so the liveness timestamp is refreshed even on a 304 that
	// arrives BEFORE this session's first apply. This grants NO trust — lastGood feeds only
	// writeCache (never ClientCAs / gen) — it just keeps written_at tracking last CP contact
	// so MAX_STALE stays meaningful regardless of poll ordering. (Today Run's first fetch is a
	// non-watch GET so a pre-apply 304 can't occur; this removes the latent coupling.)
	seed := e
	m.lastGood = &seed
	metric.TrustWarmStart(true)
	slog.Info("core: warm-start floor loaded — edge mTLS trust WITHHELD (CIDR-only) until a live fetch revalidates",
		"floor_generation", e.Generation, "ca_id", e.CAID)
}

// readCache reads + validates the warm-start file. A zero generation is invalid (it would
// be no floor at all) and is treated as a parse error so the caller cold-starts cleanly.
func readCache(path string) (cacheEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return cacheEntry{}, err
	}
	var e cacheEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return cacheEntry{}, fmt.Errorf("parse warm-start cache: %w", err)
	}
	if e.Generation == 0 {
		return cacheEntry{}, fmt.Errorf("warm-start cache has zero generation")
	}
	return e, nil
}

// writeCache persists e as the next restart's floor, always stamping written_at = now so
// the file tracks last CP contact (liveness). Best-effort: any failure logs and is ignored
// (a missing cache only loses the cross-restart guard, never breaks serving). The write is
// atomic (temp + rename) so a crash mid-write can't leave a torn file. No-op when
// persistence is disabled.
func (m *Manager) writeCache(e cacheEntry) {
	if m.cachePath == "" {
		return
	}
	e.WrittenAt = time.Now().Unix()
	data, err := json.Marshal(e)
	if err != nil {
		slog.Warn("core: warm-start cache marshal failed", "error", err)
		return
	}
	tmp := m.cachePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		slog.Warn("core: warm-start cache write failed", "path", m.cachePath, "error", err)
		return
	}
	if err := os.Rename(tmp, m.cachePath); err != nil {
		slog.Warn("core: warm-start cache rename failed", "path", m.cachePath, "error", err)
		_ = os.Remove(tmp)
	}
}

// Generation / CAID expose the last applied bundle for observability.
func (m *Manager) Generation() uint64 { return m.gen.Load() }
func (m *Manager) CAID() string {
	if s := m.caID.Load(); s != nil {
		return *s
	}
	return ""
}

// ServerTLSConfig builds the core's :443 *tls.Config. When an edge CA is loaded it
// REQUESTS an optional client cert (tls.RequestClientCert) but NEVER verifies it at the
// TLS layer — so a client cert that doesn't chain to the edge CA (e.g. Cloudflare
// Authenticated Origin Pulls) can't abort the handshake. Edge trust is decided per
// request by VerifyClientCert against the live edge-CA pool: a chaining cert is
// mTLS-trusted, anything else falls through to CIDR, and the handshake always completes.
// The SNI server cert is unchanged — getCertificate (the controller's cert table) and
// the self-signed fallback are served exactly as before.
//
// The request advertises the live edge-CA subjects (ClientCAs) so a browser connecting
// DIRECTLY to :443 can filter by them: Chromium (Chrome/Edge) and Safari offer only
// client certs chaining to the (internal) edge CA, so a normal user — who has none — is
// offered nothing and is NOT shown the certificate-selection modal. That is the reported
// symptom: a bare RequestClientCert with no advertised CAs makes those browsers offer
// EVERY client cert in the store, which is why Windows users with an enrollment/smartcard
// cert get prompted. (Firefox filters the offered list weakly, so a Firefox user with an
// unrelated personal cert may still be prompted; enterprise AutoSelectCertificateForUrls
// and smartcard-PIN prompts also live outside this filter — both pre-exist this code.)
// The edge's CP-issued cert still chains and is presented. Advertising ClientCAs does NOT
// enable TLS-layer verification — that needs ClientAuth >= VerifyClientCertIfGiven; under
// RequestClientCert it only populates the advertised CA list, so a non-chaining cert
// still can't abort the handshake. Resolved per handshake (GetConfigForClient) against
// the hot-reloaded pool, so a CA rotation is picked up without rebuilding the listener.
//
// Before any CA is loaded (cold start) nobody can be mTLS-trusted, so the core requests
// no client cert at all: a directly-connecting browser is never prompted, and the edge
// simply stays CIDR-only until the first bundle loads — the same cold-start trust outcome
// as requesting-but-not-verifying (the edge is untrusted while the pool is nil either
// way), minus the prompt. One nuance vs the old always-request config: a keep-alive
// connection the edge opens DURING cold start carries no client cert for its lifetime, so
// it stays CIDR-only until recycled (~idle timeout) even after the pool loads, instead of
// flipping to mTLS-trusted mid-connection. It self-heals on reconnect and is never an
// abort. The startup readiness gate (WaitReady / EDGE_TRUST_READY_WAIT) shrinks the window
// by holding the core NotReady until the pool loads, so the edge isn't routed here first.
func (m *Manager) ServerTLSConfig(
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error),
	fallback []tls.Certificate,
) *tls.Config {
	base := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		Certificates:   fallback,
		GetCertificate: getCertificate,
		// ClientAuth left at NoClientCert: the cold-start (nil-pool) config below
		// returns base unchanged, so no client cert is requested and no browser prompts.
	}
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		pool := m.clientCAs.Load()
		if pool == nil {
			return nil, nil // no edge CA yet → reuse base (NoClientCert): never prompt
		}
		c := base.Clone()
		c.ClientAuth = tls.RequestClientCert
		c.ClientCAs = pool // advertise the edge-CA subjects so browsers filter and skip the prompt
		return c, nil
	}
	return base
}

// VerifyClientCert reports whether the peer presented a client cert that chains to the
// live edge-CA pool (CA-only trust) — the per-request replacement for the TLS-layer
// VerifyClientCertIfGiven (see ServerTLSConfig). No cert, no loaded pool, or a cert
// that doesn't chain (Cloudflare AOP, a browser, an attacker) all return false; the
// caller then falls back to CIDR trust. A successful verify is memoized by leaf
// fingerprint for the current generation, so the edge fleet's repeated requests skip
// the x509 chain build; a pool swap (CA rotation) advances the generation and
// re-verifies.
func (m *Manager) VerifyClientCert(cs *tls.ConnectionState) bool {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return false
	}
	pool := m.clientCAs.Load()
	if pool == nil {
		return false
	}
	// Read pool before generation: apply() Stores the pool before the generation, so
	// pool-then-gen never yields (old pool, new gen) — at worst (new pool, old gen),
	// which only caches under a stale generation that the next access re-verifies.
	gen := m.gen.Load()
	sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
	key := string(sum[:])

	m.verifyMu.RLock()
	if m.verifyGen == gen {
		if v, ok := m.verifyCache[key]; ok {
			m.verifyMu.RUnlock()
			return v
		}
	}
	m.verifyMu.RUnlock()

	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	ok := err == nil

	// Cache only verified-OK results. An attacker can't mint a cert that chains to the
	// edge CA, so a flood of distinct UNtrusted certs would otherwise fill the cache and
	// evict the legit fleet's entries (cache-bust, forcing a re-verify of every real
	// edge). Not caching false defeats that: an untrusted cert just re-verifies (a cheap
	// fail) without touching the cache or the write lock. A stale-generation cached entry
	// is still rejected by the read-path gen check above; the reset below drops stale
	// entries on the first OK after a CA rotation.
	if !ok {
		return false
	}
	m.verifyMu.Lock()
	if m.verifyGen != gen || m.verifyCache == nil {
		m.verifyCache = make(map[string]bool, 64)
		m.verifyGen = gen
	}
	if len(m.verifyCache) >= verifyCacheCap {
		// Bounded: drop ONE arbitrary entry rather than wiping the whole cache, so a
		// fleet larger than the cap can't cost every other edge a re-verify at once.
		for k := range m.verifyCache {
			delete(m.verifyCache, k)
			break
		}
	}
	m.verifyCache[key] = true
	m.verifyMu.Unlock()
	return true
}

// applyResult classifies an apply attempt so the caller can emit the right metric
// (the rejection reasons are otherwise indistinguishable at a single error return).
type applyResult int

const (
	resultApplied applyResult = iota
	resultParseRejected
	resultEmptyRejected
	resultRollbackRejected
	resultFloorRejected
	resultUnchanged
)

func (r applyResult) label() string {
	switch r {
	case resultApplied:
		return "applied"
	case resultParseRejected:
		return "parse_rejected"
	case resultEmptyRejected:
		return "empty_rejected"
	case resultRollbackRejected:
		return "rollback_rejected"
	case resultFloorRejected:
		return "floor_rejected"
	case resultUnchanged:
		return "unchanged"
	default:
		return "unknown"
	}
}

// apply validate-then-swaps a bundle: strict all-or-nothing PEM parse (a non-empty
// input that yields fewer certs than CERTIFICATE blocks is rejected; never a partial
// AppendCertsFromPEM), forward-only (reject generation <= current), then atomic swap.
// It returns a typed result so Run can count the exact reason (rollback_rejected is the
// anti-replay security signal, kept distinct). Called only from the single Run goroutine.
func (m *Manager) apply(b Bundle) (applyResult, error) {
	pool, n, err := strictPool(b.CAPEM)
	if err != nil {
		return resultParseRejected, err
	}
	if n == 0 {
		return resultEmptyRejected, fmt.Errorf("trust bundle ca_pem has no certificates")
	}
	// Warm-start floor (anti-resurrection across restart): a bundle older than the persisted
	// last-good generation is a stale/rolled-back CA — reject BEFORE the in-session
	// forward-only check (this catches it even on the first post-restart apply, when cur==0).
	// floor==0 (no cache) makes this a no-op.
	if b.Generation < m.floor {
		return resultFloorRejected, fmt.Errorf("warm-start floor: bundle generation %d < persisted floor %d (stale/rolled-back CA across restart)", b.Generation, m.floor)
	}
	cur := m.gen.Load()
	if cur != 0 && b.Generation == cur {
		// Same generation as the live bundle: a benign replay, not a rollback. The
		// safety-net plain-GET poll re-fetches the current bundle in steady state (and
		// some CP long-poll implementations return the current bundle instead of a
		// 304), so this happens routinely and must NOT warn.
		return resultUnchanged, fmt.Errorf("unchanged: bundle generation %d == current %d", b.Generation, cur)
	}
	if cur != 0 && b.Generation < cur {
		return resultRollbackRejected, fmt.Errorf("rollback: bundle generation %d < current %d", b.Generation, cur)
	}
	m.clientCAs.Store(pool)
	m.gen.Store(b.Generation)
	caID := b.CAID
	m.caID.Store(&caID)
	return resultApplied, nil
}

// strictPool parses every CERTIFICATE block and fails if any block is malformed, so
// a truncated NEW block in an OLD++NEW overlap bundle is rejected (keep last-good)
// rather than half-applied.
func strictPool(caPEM []byte) (*x509.CertPool, int, error) {
	pool := x509.NewCertPool()
	rest := caPEM
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, 0, fmt.Errorf("malformed CA cert in bundle: %w", err)
		}
		pool.AddCert(c)
		n++
	}
	return pool, n, nil
}

// Run pulls the bundle once (no watch) then long-polls forever, fail-static with a
// short backoff on error. pollInterval is the safety-net fallback cadence used as
// the backoff/idle bound; the long-poll provides fast convergence.
func (m *Manager) Run(ctx context.Context, c *Client, pollInterval time.Duration) {
	if pollInterval <= 0 {
		pollInterval = 5 * time.Minute
	}
	backoff := time.Second
	first := true
	for {
		if ctx.Err() != nil {
			return
		}
		b, unchanged, err := c.Fetch(m.gen.Load(), !first)
		first = false
		switch {
		case err != nil:
			metric.TrustFetchFailed()
			slog.Warn("core: trust-bundle fetch failed; keeping last-good", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < pollInterval {
				backoff *= 2
			}
			continue
		case unchanged:
			backoff = time.Second
			// A 304 is still successful CP contact: refresh the cache's liveness timestamp so
			// MAX_STALE measures time-since-contact, not time-since-last-CA-change.
			if m.lastGood != nil {
				m.writeCache(*m.lastGood)
			}
			continue
		default:
			res, err := m.apply(b)
			metric.TrustApply(res.label())
			if res == resultUnchanged {
				// Same generation re-fetched: successful CP contact, nothing changed.
				// Refresh the liveness timestamp (like a 304) and stay quiet — this is
				// not a rollback.
				slog.Debug("core: trust-bundle unchanged (same generation)", "generation", b.Generation)
				if m.lastGood != nil {
					m.writeCache(*m.lastGood)
				}
			} else if err != nil {
				slog.Warn("core: trust-bundle rejected; keeping last-good", "error", err)
			} else {
				metric.TrustBundleApplied(b.CAID, b.Generation)
				// A live fetch revalidated trust: remember it, persist it as the next restart's
				// floor, and flip out of the warm-start (CIDR-only) degraded state.
				m.lastGood = &cacheEntry{Generation: b.Generation, CAID: b.CAID, CAPEM: string(b.CAPEM)}
				m.writeCache(*m.lastGood)
				metric.TrustWarmStart(false)
				slog.Info("core: edge trust bundle applied", "generation", b.Generation, "ca_id", b.CAID)
			}
			backoff = time.Second
		}
	}
}
