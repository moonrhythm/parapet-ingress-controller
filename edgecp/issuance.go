package edgecp

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strconv"
	"time"
)

// maxCSRBody caps the POST /v1/edge-cert body. A PKCS#10 CSR is ~1 KiB; 16 KiB is
// generous but bounds the decode. The key-type whitelist (AllowedLeafKey) — not the
// byte cap — is what bounds the verify/sign CPU cost.
const maxCSRBody = 16 << 10

// watchTimeout is the server-side long-poll block ceiling for GET
// /v1/trust-bundle?watch=1. The CP http.Server WriteTimeout/IdleTimeout must be ≥
// this (the control-plane main leaves them unset, so an unbounded write is fine).
const watchTimeout = 30 * time.Second

type edgeCertRequest struct {
	CSRPEM string `json:"csr_pem"`
}

type edgeCertResponse struct {
	ChainPEM string `json:"chain_pem"`
	NotAfter string `json:"not_after"`
	Serial   string `json:"serial"`
	CAID     string `json:"ca_id,omitempty"` // signer ca_id, so the edge self-confirms convergence post-mint
}

// handleEdgeCert signs an edge data-plane client cert from a CSR. Token-gated: a
// disabled/unknown token is 401, a token without an id grant is 403, and the
// CP-decided SAN is stamped from the token identity (the CSR's SAN is ignored).
// Absent signer ⇒ 404 (issuance not configured). The private key never appears here
// — the edge holds it; only chain_pem is returned.
func (s *Server) handleEdgeCert(w http.ResponseWriter, r *http.Request) {
	st := s.signerState.Load()
	if st == nil {
		http.Error(w, "issuance not configured", http.StatusNotFound)
		return
	}
	sg := st.sg
	token, ok := bearer(r)
	if !ok || !s.authz.Known(token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, ok := s.authz.Identity(token)
	if !ok {
		// Known token but no data-plane identity grant. Don't leak which.
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var body edgeCertRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxCSRBody)).Decode(&body); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode([]byte(body.CSRPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		http.Error(w, "csr_pem: no CERTIFICATE REQUEST block", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, "malformed CSR", http.StatusBadRequest)
		return
	}
	// Whitelist the key type/curve BEFORE verifying the signature, so an oversized
	// key can't drive a verify-DoS. Then prove possession.
	if err := AllowedLeafKey(csr.PublicKey); err != nil {
		http.Error(w, "unsupported CSR key: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, "CSR signature invalid", http.StatusBadRequest)
		return
	}

	// Fleet-aggregate backpressure: a rotation flips ca_id for every edge at once and
	// each re-mints against this CPU-bound signer. One token per edge means the
	// per-token bucket does NOT bound the aggregate, so bound the concurrent signs here
	// and shed with 503 + Retry-After when saturated — the edge coordinator honors it.
	// nil/disabled gate ⇒ no limit (behavior unchanged).
	if s.signGate != nil {
		select {
		case s.signGate <- struct{}{}:
			defer func() { <-s.signGate }()
		default:
			w.Header().Set("Retry-After", strconv.Itoa(s.signRetryAfter))
			http.Error(w, "signer saturated", http.StatusServiceUnavailable)
			return
		}
	}

	chainPEM, notAfter, serial, err := sg.Sign(csr.PublicKey, id)
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(edgeCertResponse{
		ChainPEM: string(chainPEM),
		NotAfter: notAfter.UTC().Format(time.RFC3339),
		Serial:   serial,
		CAID:     sg.CAID(),
	})
}

type trustBundleResponse struct {
	Generation uint64 `json:"generation"`
	CAPEM      string `json:"ca_pem"`
	CAID       string `json:"ca_id"`
}

// handleTrustBundle serves the tokenless trust bundle {generation, ca_pem, ca_id}
// the core pulls to populate its ClientCAs. It NEVER inspects Authorization — the
// bundle is public (ca_pem is a CA cert, ca_id a fingerprint); integrity is the
// caller-verified server-TLS, not a token. With ?watch=1&since=<gen> it long-polls:
// blocks until the generation advances past <since> or watchTimeout elapses → 304.
// Absent signer ⇒ 503 (not-yet-initialized; the core retries).
func (s *Server) handleTrustBundle(w http.ResponseWriter, r *http.Request) {
	st := s.signerState.Load()
	if st == nil {
		http.Error(w, "trust bundle not yet initialized", http.StatusServiceUnavailable)
		return
	}

	if r.URL.Query().Get("watch") == "1" {
		since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		if st.gen <= since {
			s.genMu.Lock()
			notify := s.genNotify
			s.genMu.Unlock()
			select {
			case <-notify:
			case <-time.After(watchTimeout):
			case <-r.Context().Done():
				return
			}
			// Re-load the snapshot: a SetSigner may have advanced it while we blocked.
			st = s.signerState.Load()
		}
	}

	if st == nil {
		http.Error(w, "trust bundle not yet initialized", http.StatusServiceUnavailable)
		return
	}
	sg := st.sg
	gen := st.gen
	resp := trustBundleResponse{
		Generation: gen,
		CAPEM:      string(sg.BundlePEM()),
		CAID:       sg.CAID(),
	}
	etag := etagOfString(strconv.FormatUint(gen, 10) + "\x00" + resp.CAPEM + "\x00" + resp.CAID)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if match := r.Header.Get("If-None-Match"); match != "" && etagMatch(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
