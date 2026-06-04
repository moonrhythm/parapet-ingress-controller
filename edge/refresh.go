package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"time"
)

// RefreshEdgeCertOnce generates a fresh in-memory keypair, builds a CSR, fetches a
// signed leaf from the control plane, and atomically swaps the complete cert into
// the store. Fail-static: on any error the prior cert is kept. The key is generated
// here and never written to disk — only the public-key CSR and the returned chain
// transit. The CP stamps the SAN from the token identity, so the CSR carries none.
// It returns the outcome (the parapet_edge_clientcert_remint_total result label) and,
// on a 429/503 saturated-signer shed, the Retry-After delay — so the coordinator can
// apply fleet-aggregate backpressure. trigger labels the metric (proactive|reactive|timer).
func RefreshEdgeCertOnce(cp *CpClient, store *ClientCertStore, trigger string) (result string, retryAfter time.Duration) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.Warn("edge: client keygen failed; keeping cached cert", "error", err)
		remint("keygen_fail", trigger)
		return "keygen_fail", 0
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		slog.Warn("edge: CSR build failed; keeping cached cert", "error", err)
		remint("csr_fail", trigger)
		return "csr_fail", 0
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	res, err := cp.FetchEdgeCert(csrPEM)
	if err != nil {
		slog.Warn("edge: data-plane cert fetch failed; keeping cached cert", "error", err)
		remint("fetch_fail", trigger)
		return "fetch_fail", res.RetryAfter
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		slog.Warn("edge: key marshal failed; keeping cached cert", "error", err)
		remint("marshal_fail", trigger)
		return "marshal_fail", 0
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := store.Update(res.ChainPEM, keyPEM); err != nil {
		slog.Warn("edge: data-plane cert unusable; keeping cached cert", "error", err)
		remint("store_fail", trigger)
		return "store_fail", 0
	}
	slog.Info("edge: data-plane client cert updated", "not_after", res.NotAfter, "serial", res.Serial, "ca_id", res.CAID, "trigger", trigger)
	remint("ok", trigger)
	return "ok", 0
}

// RunEdgeCertRefresh is the timer floor for the data-plane client cert. Each tick it
// (1) renews when the live leaf is within its remaining-life window (MaybeRenew) and
// (2) reads the CP target ca_id from the tokenless trust-bundle and Observes it — so an
// mTLS edge that polls neither /v1/certs nor /v1/waf (serve-all, no traffic, WAF off)
// still sees a CA rotation. Both ride THIS existing loop — no 4th goroutine. The first
// tick is jittered by [0,interval] to decorrelate the fleet's poll instants.
func RunEdgeCertRefresh(ctx context.Context, coord *RemintCoordinator, interval time.Duration) {
	if interval <= 0 {
		interval = 300 * time.Second
	}
	if !sleepCtx(ctx, fullJitter(interval)) {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			coord.MaybeRenew()
			if caID, err := coord.cp.FetchTrustBundleCAID(); err == nil {
				coord.Observe(caID)
			}
		}
	}
}

// RefreshCertOnce fetches one domain's cert from the control plane
// (ETag-revalidated) and swaps it into the store; fail-static on error. It then
// Observes the X-Parapet-CA-Id force-re-mint signal that rides EVERY response arm
// (200/304/404 — res.CAID is set even on the error arm), so a CA rotation is detected
// on the edge's existing cert poll regardless of cert outcome. coord is nil when
// data-plane mTLS is off (Observe is a no-op). Used by the periodic loop and
// (serve-all) by the on-demand TLS handshake path.
func RefreshCertOnce(cp *CpClient, store *CertStore, domain string, coord *RemintCoordinator) {
	res, err := cp.FetchCert(domain, store.Etag(domain))
	switch {
	case err != nil:
		// Fail static: keep whatever we already serve for this domain.
		slog.Warn("edge: cert fetch failed; keeping cached copy", "domain", domain, "error", err)
	case res.Unchanged:
		// 304: cached copy is current.
	default:
		if store.Update(domain, res.ChainPEM, res.KeyPEM, res.Etag) {
			slog.Info("edge: cert updated", "domain", domain)
		} else {
			slog.Warn("edge: cert PEM unparseable; keeping cached copy", "domain", domain)
		}
	}
	coord.Observe(res.CAID)
}

// RefreshCertsAll fetches every domain once (sequentially). Returns how many are
// now cached, for the startup log. coord is nil when data-plane mTLS is off.
func RefreshCertsAll(cp *CpClient, store *CertStore, domains []string, coord *RemintCoordinator) int {
	for _, d := range domains {
		RefreshCertOnce(cp, store, d, coord)
	}
	return store.Len()
}

// RunCertRefresh runs the periodic cert refresh forever. The first tick is jittered by
// [0,interval] to decorrelate the fleet's poll instants (a rotation flips ca_id for
// every edge at once; un-jittered loops would hammer GET /v1/certs in lockstep). Each
// tick refreshes the configured domains PLUS whatever is currently cached (deduped), so
// on-demand-fetched domains (serve-all mode) keep rotating and observing. Fail-static.
func RunCertRefresh(ctx context.Context, cp *CpClient, store *CertStore, domains []string, interval time.Duration, coord *RemintCoordinator) {
	if interval <= 0 { // time.NewTicker panics on a non-positive interval
		interval = 300 * time.Second
	}
	if !sleepCtx(ctx, fullJitter(interval)) {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			seen := map[string]struct{}{}
			for _, d := range append(append([]string{}, domains...), store.Keys()...) {
				if _, dup := seen[d]; dup {
					continue
				}
				seen[d] = struct{}{}
				RefreshCertOnce(cp, store, d, coord)
			}
		}
	}
}
