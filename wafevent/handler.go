package wafevent

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

const (
	defaultReadMax = 500
	maxReadMax     = 1000
)

// readResponse is the cursor endpoint's wire format (SPEC-waf-events §C.3).
type readResponse struct {
	Boot   string  `json:"boot"`
	Next   uint64  `json:"next"`
	Events []Event `json:"events"`
}

// NewHandler returns the bearer-token-authenticated cursor endpoint:
//
//	GET /waf/events?after=<seq>&boot=<bootID>&max=<n>
//
// It is meant for a dedicated cluster-local listener (WAF_EVENTS_LISTEN),
// never for exposure through a Service of type LoadBalancer or an Ingress:
// the events carry client IPs for every zone in the location, and on a flat
// cluster network tenant pods can reach the port — the token, shared with the
// in-cluster collector, is the tenant-isolation boundary. An empty token
// rejects every request (the caller should not start the listener at all in
// that case; this is defense in depth).
func NewHandler(b *Buffer, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /waf/events", func(w http.ResponseWriter, r *http.Request) {
		after, err := strconv.ParseUint(r.FormValue("after"), 10, 64)
		if err != nil {
			after = 0
		}
		max := defaultReadMax
		if v, err := strconv.Atoi(r.FormValue("max")); err == nil && v > 0 {
			max = min(v, maxReadMax)
		}
		events, next, boot := b.Read(r.FormValue("boot"), after, max)
		if events == nil {
			events = []Event{} // "events":[] — never null
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(readResponse{Boot: boot, Next: next, Events: events})
	})
	return authenticated(token, mux)
}

// authenticated gates every request behind `Authorization: Bearer <token>`
// before any routing, so unauthenticated probes learn nothing (401 for every
// path). The compare hashes both sides so it is constant-time and does not
// leak the token length.
func authenticated(token string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		got := sha256.Sum256([]byte(bearer))
		if !ok || token == "" || subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="waf-events"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
