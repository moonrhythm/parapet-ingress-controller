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
func RefreshEdgeCertOnce(cp *CpClient, store *ClientCertStore) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.Warn("edge: client keygen failed; keeping cached cert", "error", err)
		return
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		slog.Warn("edge: CSR build failed; keeping cached cert", "error", err)
		return
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	res, err := cp.FetchEdgeCert(csrPEM)
	if err != nil {
		slog.Warn("edge: data-plane cert fetch failed; keeping cached cert", "error", err)
		return
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		slog.Warn("edge: key marshal failed; keeping cached cert", "error", err)
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := store.Update(res.ChainPEM, keyPEM); err != nil {
		slog.Warn("edge: data-plane cert unusable; keeping cached cert", "error", err)
		return
	}
	slog.Info("edge: data-plane client cert updated", "not_after", res.NotAfter, "serial", res.Serial)
}

// RunEdgeCertRefresh refreshes the data-plane client cert on a timer. The first
// tick is one interval after startup (startup already fetched the first cert).
// Milestone 1 renews on the bare interval; remaining-life renewal, jitter, and the
// rotation-driven force-re-mint are follow-on (see EDGE-AUTOTRUST.md).
func RunEdgeCertRefresh(ctx context.Context, cp *CpClient, store *ClientCertStore, interval time.Duration) {
	if interval <= 0 {
		interval = 300 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			RefreshEdgeCertOnce(cp, store)
		}
	}
}

// RefreshCertOnce fetches one domain's cert from the control plane
// (ETag-revalidated) and swaps it into the store; fail-static on error. Used by
// the periodic loop and (serve-all) by the on-demand TLS path.
func RefreshCertOnce(cp *CpClient, store *CertStore, domain string) {
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
}

// RefreshCertsAll fetches every domain once (sequentially). Returns how many are
// now cached, for the startup log.
func RefreshCertsAll(cp *CpClient, store *CertStore, domains []string) int {
	for _, d := range domains {
		RefreshCertOnce(cp, store, d)
	}
	return store.Len()
}

// RunCertRefresh runs the periodic cert refresh forever. The first tick is one
// interval after startup (startup already did the full fetch). Each tick
// refreshes the configured domains PLUS whatever is currently cached (deduped),
// so on-demand-fetched domains (serve-all mode, empty domains) keep rotating.
// No backoff/jitter; fail-static is the only resilience mechanism.
func RunCertRefresh(ctx context.Context, cp *CpClient, store *CertStore, domains []string, interval time.Duration) {
	if interval <= 0 { // time.NewTicker panics on a non-positive interval
		interval = 300 * time.Second
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
				RefreshCertOnce(cp, store, d)
			}
		}
	}
}
