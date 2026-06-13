package edge

import (
	"context"
	"log/slog"
	"time"
)

// RefreshCacheOverrideOnce fetches the cache-override payload (ETag-revalidated)
// and swaps it into the EdgeCacheOverride. A fetch failure or an invalid set is
// fail-static — the edge keeps its last-good overrides and never starts forcing
// or bypassing on a degraded fetch. Per-set keep-last-good means a bad zone
// keeps its old overrides while other sets still update.
func RefreshCacheOverrideOnce(cp *CpClient, e *EdgeCacheOverride) {
	res, err := cp.FetchCache(e.Etag())
	switch {
	case err != nil:
		slog.Warn("edge: cache-override fetch failed; keeping last-good overrides", "error", err)
	case res.Unchanged:
		// 304: cached config is current.
	default:
		if err := e.Update(res.Generation, res.GlobalOverrides, res.Zones, res.RouteZoneMap, res.Etag); err != nil {
			slog.Warn("edge: a cache-override set was rejected; kept last-good (per set)", "error", err)
		} else {
			slog.Info("edge: cache overrides updated", "generation", res.Generation)
		}
	}
}

// RunCacheOverrideRefresh runs the periodic cache-override refresh forever. The
// first tick is jittered by [0,interval] (fleet poll-instant decorrelation),
// same cadence as the cert/WAF/ratelimit refresh (EDGE_REFRESH_INTERVAL);
// fail-static. poke (nil ok) wakes the loop immediately on a /v1/events change
// signal; the timer remains the fallback floor and refreshes stay single-flight.
func RunCacheOverrideRefresh(ctx context.Context, cp *CpClient, e *EdgeCacheOverride, interval time.Duration, poke <-chan struct{}) {
	if interval <= 0 { // time.NewTicker panics on a non-positive interval
		interval = 300 * time.Second
	}
	runRefreshLoop(ctx, interval, poke, func() { RefreshCacheOverrideOnce(cp, e) })
}
