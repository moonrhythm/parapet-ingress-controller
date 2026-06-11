package edge

import (
	"context"
	"log/slog"
	"time"
)

// RefreshRateLimitOnce fetches the rate-limit payload (ETag-revalidated) and
// swaps it into the EdgeRateLimit. A fetch failure or an invalid limit set is
// fail-static — the edge keeps its last-good limits and never falls open to
// "no limits". Per-set keep-last-good means a bad zone keeps its old limits
// while other sets still update.
func RefreshRateLimitOnce(cp *CpClient, e *EdgeRateLimit) {
	res, err := cp.FetchRateLimit(e.Etag())
	switch {
	case err != nil:
		slog.Warn("edge: ratelimit fetch failed; keeping last-good limits", "error", err)
	case res.Unchanged:
		// 304: cached config is current.
	default:
		if err := e.Update(res.Generation, res.GlobalLimits, res.Zones, res.HostZoneMap, res.Hosts, res.Etag); err != nil {
			slog.Warn("edge: a rate-limit set was rejected; kept last-good (per set)", "error", err)
		} else {
			slog.Info("edge: rate limits updated", "generation", res.Generation)
		}
	}
}

// RunRateLimitRefresh runs the periodic rate-limit refresh forever. The first
// tick is jittered by [0,interval] (fleet poll-instant decorrelation). Same
// cadence as the cert/WAF refresh (EDGE_REFRESH_INTERVAL); fail-static.
func RunRateLimitRefresh(ctx context.Context, cp *CpClient, e *EdgeRateLimit, interval time.Duration) {
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
			RefreshRateLimitOnce(cp, e)
		}
	}
}
