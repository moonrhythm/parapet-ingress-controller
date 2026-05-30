package edgecp

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Server is the edge control-plane HTTP API. It authorizes each request by the
// edge's bearer token (see Authz), then serves the cert+key for an allowed SNI.
// WAF distribution (GET /v1/waf) is added via WithWAF. See ../../EDGE.md.
type Server struct {
	certs *CertStore
	authz *Authz
	waf   *WafStore // optional (nil = WAF distribution disabled, /v1/waf → 404)
}

func NewServer(certs *CertStore, authz *Authz) *Server {
	return &Server{certs: certs, authz: authz}
}

// WithWAF enables the global-ruleset endpoint (Phase 2). Returns the server for
// chaining.
func (s *Server) WithWAF(waf *WafStore) *Server {
	s.waf = waf
	return s
}

// Handler returns the mux. Mount behind HTTPS (the API ships private keys).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/certs", s.handleCert)
	mux.HandleFunc("GET /v1/waf", s.handleWAF)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	return mux
}

// handleHealthz is both the liveness and readiness probe. Plain `GET /healthz`
// is liveness (always 200 while the process is up). `GET /healthz?ready=1` is
// readiness: 200 only once the cert store has loaded at least once (the initial
// list from the cluster succeeded), else 503 — so an edge isn't pointed at a
// control plane that can't yet serve certs.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("ready") == "1" && !s.certs.Loaded() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
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
	Zones       map[string]string `json:"zones"`         // zoneKey -> rules YAML
	HostZoneMap map[string]string `json:"host_zone_map"` // host -> zoneKey
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
