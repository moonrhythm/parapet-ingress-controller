// Package trust lets the in-cluster core proxy pull its edge-CA trust anchor from
// the control plane over verified server-TLS, instead of watching a k8s Secret.
// The bundle is tokenless (it carries only the public CA cert + a fingerprint;
// integrity is the caller-verified server-TLS, not a token). The core trusts any
// edge leaf that chains to this CA — CA-only trust. See EDGE-AUTOTRUST.md.
package trust

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
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

// Client is the tokenless HTTPS client to the control plane's GET /v1/trust-bundle.
// Server-TLS verification is MANDATORY and non-skippable: it is the sole integrity
// guarantee that justifies dropping the bearer token (a forged bundle would be a
// trust-boundary takeover). NewClient fails if the CP server CA can't be loaded.
type Client struct {
	http *http.Client
	base string
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

// Manager holds the live edge-CA pool the core's :443 GetConfigForClient reads per
// handshake, hot-swapped from the CP bundle with strict-parse + forward-only +
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
}

func NewManager() *Manager { return &Manager{} }

// ClientCAs returns the live pool (nil before the first successful load — the
// caller then requests-but-does-not-verify client certs so the cold-start window
// degrades to CIDR-only rather than aborting edge handshakes).
func (m *Manager) ClientCAs() *x509.CertPool { return m.clientCAs.Load() }

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

// ServerTLSConfig builds the core's :443 *tls.Config so it verifies an OPTIONAL
// edge client cert against the live, hot-reloaded CA pool — CA-only trust. The SNI
// server cert is unchanged: getCertificate (the controller's cert table) and the
// self-signed fallback are served exactly as before. Per handshake, ClientCAs is
// loaded fresh from the manager; before the bundle loads (pool nil) it
// requests-but-does-not-verify (tls.RequestClientCert) so the cold-start window
// degrades to CIDR-only rather than aborting edge handshakes. Once loaded it is
// tls.VerifyClientCertIfGiven (no cert → fine; a presented cert must verify to the
// edge CA, else the handshake aborts). A verified cert populates
// r.TLS.VerifiedChains, which the per-request trust predicate keys on.
func (m *Manager) ServerTLSConfig(
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error),
	fallback []tls.Certificate,
) *tls.Config {
	base := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		Certificates:   fallback,
		GetCertificate: getCertificate,
		ClientAuth:     tls.RequestClientCert,
	}
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := &tls.Config{
			MinVersion:     tls.VersionTLS12,
			Certificates:   fallback,
			GetCertificate: getCertificate,
		}
		if pool := m.ClientCAs(); pool != nil {
			c.ClientCAs = pool
			c.ClientAuth = tls.VerifyClientCertIfGiven
		} else {
			c.ClientAuth = tls.RequestClientCert
		}
		return c, nil
	}
	return base
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
	if cur != 0 && b.Generation <= cur {
		return resultRollbackRejected, fmt.Errorf("rollback: bundle generation %d <= current %d", b.Generation, cur)
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
			if err != nil {
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
