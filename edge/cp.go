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
	"strings"
	"time"
)

// Response body caps: a compromised/buggy control plane shouldn't be able to
// OOM the edge during decode. Generous but finite (a cert+key is a few KiB; a
// WAF ruleset bundle for many zones can be larger).
const (
	maxCertBody = 4 << 20  // 4 MiB
	maxWafBody  = 64 << 20 // 64 MiB
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

	switch resp.StatusCode {
	case http.StatusNotModified:
		return CertFetch{Unchanged: true}, nil
	case http.StatusOK:
		var body certBody
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxCertBody)).Decode(&body); err != nil {
			return CertFetch{}, fmt.Errorf("decode: %w", err)
		}
		return CertFetch{
			ChainPEM: []byte(body.ChainPEM),
			KeyPEM:   []byte(body.KeyPEM),
			Etag:     resp.Header.Get("ETag"),
		}, nil
	default:
		return CertFetch{}, fmt.Errorf("control plane returned %d for sni %q", resp.StatusCode, sni)
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
}

type wafBody struct {
	Generation  uint64            `json:"generation"`
	GlobalRules string            `json:"global_rules"`
	Zones       map[string]string `json:"zones"`
	HostZoneMap map[string]string `json:"host_zone_map"`
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
		}, nil
	default:
		return WafFetch{}, fmt.Errorf("control plane returned %d for /v1/waf", resp.StatusCode)
	}
}

// EdgeCertFetch is the outcome of a data-plane client-cert issuance.
type EdgeCertFetch struct {
	ChainPEM []byte // leaf-first chain (leaf + edge CA); pair with the locally-held key
	NotAfter string // RFC3339, for renewal scheduling
	Serial   string
}

type edgeCertReqBody struct {
	CSRPEM string `json:"csr_pem"`
}

type edgeCertRespBody struct {
	ChainPEM string `json:"chain_pem"`
	NotAfter string `json:"not_after"`
	Serial   string `json:"serial"`
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
		return EdgeCertFetch{}, fmt.Errorf("control plane returned %d for /v1/edge-cert", resp.StatusCode)
	}
	var body edgeCertRespBody
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxCertBody)).Decode(&body); err != nil {
		return EdgeCertFetch{}, fmt.Errorf("decode: %w", err)
	}
	return EdgeCertFetch{
		ChainPEM: []byte(body.ChainPEM),
		NotAfter: body.NotAfter,
		Serial:   body.Serial,
	}, nil
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
