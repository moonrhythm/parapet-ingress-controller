package edgecp

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// Server is the edge control-plane HTTP API. It authorizes each request by the
// edge's bearer token (see Authz), then serves the cert+key for an allowed SNI.
// WAF distribution (GET /v1/waf) is added via WithWAF; data-plane client-cert
// issuance (POST /v1/edge-cert) and the tokenless trust bundle
// (GET /v1/trust-bundle) via WithSigner. See ../EDGE.md.
type Server struct {
	certs *CertStore
	authz *Authz
	waf   *WafStore // optional (nil = WAF distribution disabled, /v1/waf → 404)

	// signerState is the (signer, generation) snapshot, replaced WHOLESALE by
	// SetSigner so a reader Loads both halves coherently (never a torn signer-from-A
	// + gen-from-B). nil ⇒ /v1/edge-cert 404s and /v1/trust-bundle 503s (issuance
	// not yet initialized). It is an atomic.Pointer so a CA rotation can hot-swap it
	// without restarting. genNotify is closed-and-replaced on each bump to wake
	// long-poll waiters. See handleTrustBundle.
	signerState atomic.Pointer[signerGen]
	genMu       sync.Mutex
	genNotify   chan struct{}

	// issuanceExpected gates readiness: once set (issuance was configured), the
	// readiness probe 503s until a signer has actually loaded, so an edge isn't
	// pointed at a CP that can't yet issue/serve the trust bundle.
	issuanceExpected atomic.Bool

	// signGate bounds concurrent sg.Sign() on POST /v1/edge-cert (nil = no limit).
	// When full, the handler sheds with 503 + Retry-After:signRetryAfter — the
	// fleet-aggregate backpressure during a rotation's re-mint surge.
	signGate       chan struct{}
	signRetryAfter int
}

// WithSignConcurrency bounds concurrent edge-cert signing: at most n in flight, with
// the given Retry-After (seconds) on a shed 503. n <= 0 disables the limit. Returns
// the server for chaining; call once at startup.
func (s *Server) WithSignConcurrency(n, retryAfterSecs int) *Server {
	if n > 0 {
		s.signGate = make(chan struct{}, n)
	}
	if retryAfterSecs <= 0 {
		retryAfterSecs = 5
	}
	s.signRetryAfter = retryAfterSecs
	return s
}

// signerGen is an immutable (signer, generation) pair. SetSigner replaces the whole
// value under genMu; readers Load it once and read both fields from the same value.
type signerGen struct {
	sg  *Signer
	gen uint64
}

func NewServer(certs *CertStore, authz *Authz) *Server {
	return &Server{certs: certs, authz: authz, genNotify: make(chan struct{})}
}

// WithWAF enables the global-ruleset endpoint (Phase 2). Returns the server for
// chaining.
func (s *Server) WithWAF(waf *WafStore) *Server {
	s.waf = waf
	return s
}

// WithSigner enables data-plane client-cert issuance and trust distribution at the
// given trust-bundle generation. Returns the server for chaining.
func (s *Server) WithSigner(sg *Signer, generation uint64) *Server {
	s.SetSigner(sg, generation)
	return s
}

// SetSigner installs (or hot-swaps, on rotation) the active Signer at the given
// trust-bundle generation. generation is the CA Secret's resourceVersion (the etcd
// revision — replica-identical + monotonic across CP replicas), NOT a process counter.
//
// It enforces a MONOTONIC FLOOR: a generation <= the currently-served one is rejected
// (kept last-good, counted), so an out-of-order watch re-list serving an older cached CA
// object can never regress the served generation — which would otherwise let the core
// re-apply a replayed-older bundle (re-trusting a dropped CA / un-trusting a re-minted
// fleet). The (signer, gen) pair is one immutable value so concurrent readers never tear
// it. Safe to call concurrently.
func (s *Server) SetSigner(sg *Signer, generation uint64) {
	s.genMu.Lock()
	defer s.genMu.Unlock()
	if st := s.signerState.Load(); st != nil && generation <= st.gen {
		signerFloored.Inc()
		return
	}
	s.signerState.Store(&signerGen{sg: sg, gen: generation})
	// Convergence metrics: set all signer gauges together inside the held genMu so a
	// scrape never tears across them. Done before close(genNotify) so a long-poll
	// waiter that wakes and re-scrapes always observes the new series.
	setSignerMetrics(sg.CAID(), generation, sg.BundleLen())
	close(s.genNotify)
	s.genNotify = make(chan struct{})
}

// CurrentCAID returns the live signer's ca_id, or "" if no signer is loaded. The
// serving reloader compares it to a rebuilt candidate to gate SetSigner (a no-op
// re-list must not churn the generation).
func (s *Server) CurrentCAID() string {
	if st := s.signerState.Load(); st != nil && st.sg != nil {
		return st.sg.CAID()
	}
	return ""
}

// SignerLoaded reports whether a signer has been installed (issuance is live).
func (s *Server) SignerLoaded() bool { return s.signerState.Load() != nil }

// ExpectIssuance marks that issuance was configured, so readiness gates on a loaded
// signer. Call once at startup when an edge CA (managed or provided) is wired.
func (s *Server) ExpectIssuance() { s.issuanceExpected.Store(true) }

// Handler returns the mux. Mount behind HTTPS (the API ships private keys).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/certs", s.handleCert)
	mux.HandleFunc("GET /v1/waf", s.handleWAF)
	mux.HandleFunc("POST /v1/edge-cert", s.handleEdgeCert)
	mux.HandleFunc("GET /v1/trust-bundle", s.handleTrustBundle)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	return mux
}

// handleHealthz is both the liveness and readiness probe. Plain `GET /healthz`
// is liveness (always 200 while the process is up). `GET /healthz?ready=1` is
// readiness: 200 only once the cert store has loaded at least once (the initial
// list from the cluster succeeded), else 503 — so an edge isn't pointed at a
// control plane that can't yet serve certs.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("ready") == "1" {
		if !s.certs.Loaded() {
			http.Error(w, "not ready: certs", http.StatusServiceUnavailable)
			return
		}
		if s.issuanceExpected.Load() && !s.SignerLoaded() {
			http.Error(w, "not ready: signer", http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

type certResponse struct {
	ChainPEM string `json:"chain_pem"`
	KeyPEM   string `json:"key_pem"`
}

// handleCert serves the cert+key for the `sni` query parameter
// (GET /v1/certs?sni=<host>), authorized by the bearer token.
func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok || !s.authz.Known(token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sni := r.URL.Query().Get("sni")
	if sni == "" {
		http.Error(w, "missing sni query parameter", http.StatusBadRequest)
		return
	}
	if !s.authz.Allowed(token, sni) {
		// Don't reveal whether the cert exists to an unauthorized caller.
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Force-re-mint signal: advertise the signer's target ca_id (the edge-CA the fleet
	// should converge to, process-global) on EVERY authorized response — 404/304/200 —
	// so an edge observes a CA rotation on its existing /v1/certs poll regardless of
	// cert presence or ETag state. This is the SIGNER target, orthogonal to this sni's
	// leaf issuer; it is deliberately NOT folded into entry.etag — a pure CA rotation
	// must never force a fleet-wide cert+key re-download. Set after Known()/Allowed()
	// (never to an unauthorized caller), before any WriteHeader so it rides the 304/404.
	if id := s.CurrentCAID(); id != "" {
		w.Header().Set("X-Parapet-CA-Id", id)
	}

	entry, ok := s.certs.Get(sni)
	if !ok {
		http.Error(w, "no certificate for sni", http.StatusNotFound)
		return
	}

	// ETag revalidation: the edge sends its cached validator; unchanged → 304.
	w.Header().Set("ETag", entry.etag)
	if match := r.Header.Get("If-None-Match"); match != "" && etagMatch(match, entry.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // a private key must not be cached by intermediaries
	_ = json.NewEncoder(w).Encode(certResponse{
		ChainPEM: string(entry.chainPEM),
		KeyPEM:   string(entry.keyPEM),
	})
}

type wafResponse struct {
	Generation  uint64            `json:"generation"`
	GlobalRules string            `json:"global_rules"`
	Zones       map[string]string `json:"zones"`           // zoneKey -> rules YAML
	HostZoneMap map[string]string `json:"host_zone_map"`   // host -> zoneKey
	CAID        string            `json:"ca_id,omitempty"` // signer target ca_id (best-effort SECONDARY force-re-mint confirmer)
}

// handleWAF serves the WAF payload scoped to the edge's allowed domains: the
// global baseline (identical for every edge) plus only the zones and host→zone
// bindings for hosts this token may serve. ETag is computed over the *scoped*
// payload, so revalidation is correct per edge.
func (s *Server) handleWAF(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok || !s.authz.Known(token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.waf == nil {
		http.Error(w, "waf distribution disabled", http.StatusNotFound)
		return
	}
	snap := s.waf.scoped(func(host string) bool { return s.authz.Allowed(token, host) })
	resp := wafResponse{
		Generation:  snap.generation,
		GlobalRules: snap.global,
		Zones:       snap.zones,
		HostZoneMap: snap.hostZone,
		// In-body ca_id busts the ETag on the 200 arm for free (the WAF snapshot is
		// ca_id-independent — SetSigner leaves it untouched). The steady-state 304 arm
		// carries NOTHING, so /v1/waf is only a SECONDARY confirmer; the /v1/certs
		// X-Parapet-CA-Id header is the guaranteed steady-state carrier.
		CAID: s.CurrentCAID(),
	}
	body, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	// ETag over the scoped bytes (per-edge content differs, so per-edge etag).
	etag := etagOfString(string(body))
	w.Header().Set("ETag", etag)
	if match := r.Header.Get("If-None-Match"); match != "" && etagMatch(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// bearer extracts the token from an "Authorization: Bearer <token>" header.
func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", false
	}
	return strings.TrimSpace(h[len(p):]), true
}

// etagMatch handles a comma-separated If-None-Match list (and "*").
func etagMatch(ifNoneMatch, etag string) bool {
	for _, tok := range strings.Split(ifNoneMatch, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "*" || tok == etag {
			return true
		}
	}
	return false
}
