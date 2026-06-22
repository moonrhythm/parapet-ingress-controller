package edge

import (
	"context"
	"log/slog"
	"time"
)

// RefreshCorazaOnce fetches the Coraza payload (ETag-revalidated) and swaps it
// into the EdgeCoraza. A fetch failure or a compile error is fail-static — the
// edge keeps its last-good ruleset and never falls open to "no Coraza".
// Per-ruleset keep-last-good means a bad zone keeps its old rules while other
// rulesets still update.
func RefreshCorazaOnce(cp *CpClient, c *EdgeCoraza) {
	res, err := cp.FetchCoraza(c.Etag())
	switch {
	case err != nil:
		slog.Warn("edge: Coraza fetch failed; keeping last-good ruleset", "error", err)
	case res.Unchanged:
		// 304: cached ruleset is current.
	default:
		if err := c.Update(res.Generation, res.GlobalRules, res.Zones, res.RouteZoneMap, res.Etag); err != nil {
			slog.Warn("edge: a Coraza ruleset was rejected; kept last-good (per ruleset)", "error", err)
		} else {
			slog.Info("edge: Coraza rulesets updated", "generation", res.Generation)
		}
	}
}

// RunCorazaRefresh runs the periodic Coraza refresh forever. The first tick is
// jittered by [0,interval]; same cadence as the WAF refresh (EDGE_REFRESH_INTERVAL),
// fail-static. poke (nil ok) wakes the loop immediately on a /v1/events change
// signal, so the timer is only the fallback floor.
func RunCorazaRefresh(ctx context.Context, cp *CpClient, c *EdgeCoraza, interval time.Duration, poke <-chan struct{}) {
	if interval <= 0 {
		interval = 300 * time.Second
	}
	runRefreshLoop(ctx, interval, poke, func() { RefreshCorazaOnce(cp, c) })
}
