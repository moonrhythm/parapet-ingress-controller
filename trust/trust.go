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
	"strconv"
	"sync/atomic"
	"time"
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
type Manager struct {
	clientCAs atomic.Pointer[x509.CertPool]
	gen       atomic.Uint64
	caID      atomic.Pointer[string]
}

func NewManager() *Manager { return &Manager{} }

// ClientCAs returns the live pool (nil before the first successful load — the
// caller then requests-but-does-not-verify client certs so the cold-start window
// degrades to CIDR-only rather than aborting edge handshakes).
func (m *Manager) ClientCAs() *x509.CertPool { return m.clientCAs.Load() }

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

// apply validate-then-swaps a bundle: strict all-or-nothing PEM parse (a non-empty
// input that yields fewer certs than CERTIFICATE blocks is rejected; never a partial
// AppendCertsFromPEM), forward-only (reject generation <= current), then atomic swap.
func (m *Manager) apply(b Bundle) error {
	pool, n, err := strictPool(b.CAPEM)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("trust bundle ca_pem has no certificates")
	}
	cur := m.gen.Load()
	if cur != 0 && b.Generation <= cur {
		return fmt.Errorf("rollback: bundle generation %d <= current %d", b.Generation, cur)
	}
	m.clientCAs.Store(pool)
	m.gen.Store(b.Generation)
	caID := b.CAID
	m.caID.Store(&caID)
	return nil
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
			continue
		default:
			if err := m.apply(b); err != nil {
				slog.Warn("core: trust-bundle rejected; keeping last-good", "error", err)
			} else {
				slog.Info("core: edge trust bundle applied", "generation", b.Generation, "ca_id", b.CAID)
			}
			backoff = time.Second
		}
	}
}
