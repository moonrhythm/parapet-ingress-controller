package edge

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Response body caps: a compromised/buggy control plane shouldn't be able to
// OOM the edge during decode. Generous but finite (a cert+key is a few KiB; a
// WAF ruleset bundle for many zones can be larger).
const (
	maxCertBody  = 4 << 20  // 4 MiB
	maxWafBody   = 64 << 20 // 64 MiB
	maxPurgeBody = 16 << 20 // 16 MiB (a journal page of {seq,scope,host,uri} records)
)

// CpClient is the HTTPS client to the in-cluster control plane. It presents the
// edge's bearer token and revalidates cert/WAF material with ETags. The token
// and the returned private key only ever travel over this connection. Mirrors
// the Rust edge's CpClient: GET /v1/certs?sni= and GET /v1/waf, fail-static.
type CpClient struct {
	http  *http.Client
	base  string
	token string
}

// NewCpClient builds a client for base (e.g. https://controlplane:8443). caPEM,
// when non-empty, is added as a trusted root (for a private CA); an unparseable
// CA is ignored (system roots are used). A bad/empty base is reported.
func NewCpClient(base, token string, caPEM []byte) (*CpClient, error) {
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("edge: invalid control-plane endpoint %q: %w", base, err)
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caPEM) {
			tlsConfig.RootCAs = pool
		}
	}
	return &CpClient{
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
		base:  strings.TrimRight(base, "/"),
		token: token,
	}, nil
}

// CertFetch is the outcome of a cert fetch.
type CertFetch struct {
	// Unchanged is true on a 304 (the edge's cached copy is current).
	Unchanged bool
	// ChainPEM/KeyPEM/Etag carry new material on a 200.
	ChainPEM []byte
	KeyPEM   []byte
	Etag     string
	// CAID is the signer's target ca_id from the X-Parapet-CA-Id response header. It
	// is populated on EVERY status (200, 304, and even a 404) — the universal
	// force-re-mint signal that rides the edge's existing /v1/certs poll. "" means the
	// CP didn't advertise one (old CP / no signer); the edge fail-statics on "".
	CAID string
	// SignerFP is the CP's active signing fp from X-Parapet-Signing-Cert-Fp (every arm) —
	// the tuple's other half: an active=OLD→NEW flip changes THIS at an identical CAID,
	// so the edge must re-mint on the (CAID, SignerFP) tuple to obtain a NEW-signed leaf.
	SignerFP string
}

type certBody struct {
	ChainPEM string `json:"chain_pem"`
	KeyPEM   string `json:"key_pem"`
}

// FetchCert fetches the cert+key for sni with ETag revalidation. The sni is
// percent-encoded into ?sni= so a wildcard like *.acme.com transmits safely.
// Returns an error on any non-200/304 status (incl. 403/404) — the caller is
// fail-static. The ETag is carried verbatim (quotes included).
func (c *CpClient) FetchCert(sni, currentEtag string) (CertFetch, error) {
	u := c.base + "/v1/certs?sni=" + url.QueryEscape(sni)
	resp, err := c.do(u, currentEtag)
	if err != nil {
		return CertFetch{}, err
	}
	defer resp.Body.Close()

	// The X-Parapet-CA-Id header rides EVERY status. Read it once, up front, so the
	// force-re-mint signal is surfaced on the 304 (the steady-state carrier — almost
	// all responses are 304), the 200, AND the 404 (a missing-cert sni still learns
	// the CP target). Steady state is ~100% 304s, so the 304 arm is load-bearing.
	caID := resp.Header.Get("X-Parapet-CA-Id")
	signerFP := resp.Header.Get("X-Parapet-Signing-Cert-Fp")
	switch resp.StatusCode {
	case http.StatusNotModified:
		return CertFetch{Unchanged: true, CAID: caID, SignerFP: signerFP}, nil
	case http.StatusOK:
		var body certBody
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxCertBody)).Decode(&body); err != nil {
			return CertFetch{}, fmt.Errorf("decode: %w", err)
		}
		return CertFetch{
			ChainPEM: []byte(body.ChainPEM),
			KeyPEM:   []byte(body.KeyPEM),
			Etag:     resp.Header.Get("ETag"),
			CAID:     caID,
			SignerFP: signerFP,
		}, nil
	default:
		// Surface the target with the error so the caller can still observe a flip
		// even when the per-sni cert is missing (404).
		return CertFetch{CAID: caID, SignerFP: signerFP}, fmt.Errorf("control plane returned %d for sni %q", resp.StatusCode, sni)
	}
}

// WafFetch is the outcome of a WAF ruleset fetch.
type WafFetch struct {
	// Unchanged is true on a 304.
	Unchanged bool
	// On a 200: the generation, global YAML, per-zone YAML, host->zone bindings,
	// and the ETag.
	Generation  uint64
	GlobalRules string
	Zones       map[string]string
	HostZoneMap map[string]string
	Etag        string
	CAID        string // signer target ca_id (secondary force-re-mint confirmer; 200 only)
	SignerFP    string // active signing fp (200 only)
}

type wafBody struct {
	Generation  uint64            `json:"generation"`
	GlobalRules string            `json:"global_rules"`
	Zones       map[string]string `json:"zones"`
	HostZoneMap map[string]string `json:"host_zone_map"`
	CAID        string            `json:"ca_id"`
	SigningFP   string            `json:"signing_cert_fp"`
}

// FetchWaf fetches the WAF payload (global YAML + zones + host->zone map) scoped
// to the edge's token, with ETag revalidation. A 404 ("waf distribution
// disabled") is treated like any other non-200/304: an error the caller handles
// fail-static (keeps last-good).
func (c *CpClient) FetchWaf(currentEtag string) (WafFetch, error) {
	resp, err := c.do(c.base+"/v1/waf", currentEtag)
	if err != nil {
		return WafFetch{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return WafFetch{Unchanged: true}, nil
	case http.StatusOK:
		var body wafBody
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxWafBody)).Decode(&body); err != nil {
			return WafFetch{}, fmt.Errorf("decode: %w", err)
		}
		return WafFetch{
			Generation:  body.Generation,
			GlobalRules: body.GlobalRules,
			Zones:       body.Zones,
			HostZoneMap: body.HostZoneMap,
			Etag:        resp.Header.Get("ETag"),
			CAID:        body.CAID,
			SignerFP:    body.SigningFP,
		}, nil
	default:
		return WafFetch{}, fmt.Errorf("control plane returned %d for /v1/waf", resp.StatusCode)
	}
}

// PurgeFetch is the outcome of a cache-purge poll.
type PurgeFetch struct {
	// Disabled is true on a 404 ("purge distribution disabled" at the CP): a clean,
	// expected off-state the caller skips quietly (distinct from an unreachable CP).
	Disabled bool
	// FlushRequired is true when the edge's cursor fell behind the CP's retained
	// journal — the edge bumps its global epoch (lazy flush-all) and jumps to MaxSeq.
	FlushRequired bool
	// Entries are the new purges (seq > the requested cursor), already scoped to this
	// edge's allowed hosts by the CP.
	Entries []PurgeEntry
	// MaxSeq is the highest journal seq; the edge advances its cursor to it.
	MaxSeq uint64
}

type purgeBody struct {
	Entries       []PurgeEntry `json:"entries"`
	MaxSeq        uint64       `json:"max_seq"`
	FlushRequired bool         `json:"flush_required"`
}

// FetchPurges polls GET /v1/purges?since=<cursor> for cache-purge directives the
// edge hasn't applied. A 404 returns Disabled=true (err nil) so the caller can skip
// quietly when the CP isn't distributing purges; any other non-200 is an error the
// caller handles fail-static (keeps its applied epochs + cursor). No ETag: the
// since-cursor already makes the poll incremental and idempotent.
func (c *CpClient) FetchPurges(since uint64) (PurgeFetch, error) {
	u := c.base + "/v1/purges?since=" + strconv.FormatUint(since, 10)
	resp, err := c.do(u, "")
	if err != nil {
		return PurgeFetch{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return PurgeFetch{Disabled: true}, nil
	case http.StatusOK:
		var body purgeBody
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxPurgeBody)).Decode(&body); err != nil {
			return PurgeFetch{}, fmt.Errorf("decode: %w", err)
		}
		return PurgeFetch{
			FlushRequired: body.FlushRequired,
			Entries:       body.Entries,
			MaxSeq:        body.MaxSeq,
		}, nil
	default:
		return PurgeFetch{}, fmt.Errorf("control plane returned %d for /v1/purges", resp.StatusCode)
	}
}

// EdgeCertFetch is the outcome of a data-plane client-cert issuance.
type EdgeCertFetch struct {
	ChainPEM []byte // leaf-first chain (leaf + edge CA); pair with the locally-held key
	NotAfter string // RFC3339, for renewal scheduling
	Serial   string
	CAID     string // signer ca_id, so the edge self-confirms convergence post-mint
	SignerFP string // active signing fp that minted this leaf
	// RetryAfter is the parsed Retry-After delay on a 429/503 (signer saturated),
	// returned ALONGSIDE the error so the coordinator can back off the whole fleet.
	RetryAfter time.Duration
}

type edgeCertReqBody struct {
	CSRPEM string `json:"csr_pem"`
}

type edgeCertRespBody struct {
	ChainPEM  string `json:"chain_pem"`
	NotAfter  string `json:"not_after"`
	Serial    string `json:"serial"`
	CAID      string `json:"ca_id"`
	SigningFP string `json:"signing_cert_fp"`
}

// FetchEdgeCert posts a CSR to POST /v1/edge-cert and returns the signed chain. The
// edge holds the matching private key locally; only the public-key CSR and the
// chain transit. Any non-200 is an error the caller handles fail-static (keeps the
// last-good in-memory cert).
func (c *CpClient) FetchEdgeCert(csrPEM []byte) (EdgeCertFetch, error) {
	reqBody, err := json.Marshal(edgeCertReqBody{CSRPEM: string(csrPEM)})
	if err != nil {
		return EdgeCertFetch{}, err
	}
	req, err := http.NewRequest(http.MethodPost, c.base+"/v1/edge-cert", bytes.NewReader(reqBody))
	if err != nil {
		return EdgeCertFetch{}, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return EdgeCertFetch{}, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		// On a saturated-signer shed (429/503), surface the Retry-After so the
		// coordinator honors fleet-aggregate backpressure (one token per edge does NOT
		// bound the aggregate). Returned with the error; the caller still fail-statics.
		var retryAfter time.Duration
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
		}
		return EdgeCertFetch{RetryAfter: retryAfter}, fmt.Errorf("control plane returned %d for /v1/edge-cert", resp.StatusCode)
	}
	var body edgeCertRespBody
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxCertBody)).Decode(&body); err != nil {
		return EdgeCertFetch{}, fmt.Errorf("decode: %w", err)
	}
	return EdgeCertFetch{
		ChainPEM: []byte(body.ChainPEM),
		NotAfter: body.NotAfter,
		Serial:   body.Serial,
		CAID:     body.CAID,
		SignerFP: body.SigningFP,
	}, nil
}

// parseRetryAfter parses an HTTP Retry-After header value: either delta-seconds
// (e.g. "5") or an HTTP-date. Returns 0 on empty/unparseable/negative.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

type trustBundleBody struct {
	CAID      string `json:"ca_id"`
	SigningFP string `json:"signing_cert_fp"`
}

// FetchTrustBundleSignal reads the (ca_id, active signer fp) tuple from the tokenless GET
// /v1/trust-bundle (the same public endpoint the core polls). It lets an mTLS edge observe
// a CA rotation OR an active=OLD→NEW flip even when it polls no per-domain cert and no WAF
// (serve-all, no traffic, WAF off) — it rides the edge-cert refresh tick, not a new loop.
// The bearer token is sent (the endpoint ignores it). Errors are the caller's to
// fail-static on.
func (c *CpClient) FetchTrustBundleSignal() (caID, signerFP string, err error) {
	resp, err := c.do(c.base+"/v1/trust-bundle", "")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("control plane returned %d for /v1/trust-bundle", resp.StatusCode)
	}
	var body trustBundleBody
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxCertBody)).Decode(&body); err != nil {
		return "", "", fmt.Errorf("decode: %w", err)
	}
	return body.CAID, body.SigningFP, nil
}

// do issues an authorized GET, optionally with If-None-Match. The body must be
// closed by the caller.
func (c *CpClient) do(rawURL, ifNoneMatch string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	// Drain non-200/304 bodies so the connection can be reused, but keep the
	// body open for the caller on 200.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	}
	return resp, nil
}
