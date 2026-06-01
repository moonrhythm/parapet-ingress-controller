package edge

import (
	"context"
	"log/slog"
	"time"
)

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
