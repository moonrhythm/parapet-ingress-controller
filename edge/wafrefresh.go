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
func RefreshWafOnce(cp *CpClient, w *EdgeWAF, coord *RemintCoordinator) {
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
	// Secondary force-re-mint confirmer: the WAF body carries ca_id on the 200 arm only
	// (the 304 carries nothing — /v1/certs is the guaranteed carrier). res.CAID is ""
	// on 304/err, and Observe("") is a no-op.
	coord.Observe(res.CAID)
}

// RunWafRefresh runs the periodic WAF refresh forever. The first tick is jittered by
// [0,interval] (fleet poll-instant decorrelation). Same cadence as the cert refresh
// (EDGE_REFRESH_INTERVAL); fail-static.
func RunWafRefresh(ctx context.Context, cp *CpClient, w *EdgeWAF, interval time.Duration, coord *RemintCoordinator) {
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
			RefreshWafOnce(cp, w, coord)
		}
	}
}
