package edge

import (
	"context"
	"log/slog"
	"time"
)

// RefreshWafOnce fetches the WAF payload (ETag-revalidated) and swaps it into the
// EdgeWAF. A fetch failure or a compile error is fail-static — the edge keeps its
// last-good ruleset and never falls open to "no WAF". Per-ruleset keep-last-good
// means a bad zone keeps its old rules while other rulesets still update.
func RefreshWafOnce(cp *CpClient, w *EdgeWAF) {
	res, err := cp.FetchWaf(w.Etag())
	switch {
	case err != nil:
		slog.Warn("edge: WAF fetch failed; keeping last-good ruleset", "error", err)
	case res.Unchanged:
		// 304: cached ruleset is current.
	default:
		if err := w.Update(res.Generation, res.GlobalRules, res.Zones, res.HostZoneMap, res.Etag); err != nil {
			slog.Warn("edge: a WAF ruleset was rejected; kept last-good (per ruleset)", "error", err)
		} else {
			slog.Info("edge: WAF rulesets updated", "generation", res.Generation)
		}
	}
}

// RunWafRefresh runs the periodic WAF refresh forever. The first tick is one
// interval after startup (startup already fetched). Same cadence as the cert
// refresh (EDGE_REFRESH_INTERVAL); fail-static.
func RunWafRefresh(ctx context.Context, cp *CpClient, w *EdgeWAF, interval time.Duration) {
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
			RefreshWafOnce(cp, w)
		}
	}
}
