package edge

import (
	"context"
	"log/slog"
	"time"
)

// RefreshHostsOnce fetches the known-host list (ETag-revalidated) and swaps it
// into EdgeHosts. A fetch failure is fail-static — the metric keeps its current
// host bound. There is no compile step, so a 200 always applies.
func RefreshHostsOnce(cp *CpClient, h *EdgeHosts) {
	res, err := cp.FetchHosts(h.Etag())
	switch {
	case err != nil:
		slog.Warn("edge: hosts fetch failed; keeping last-good known-host set", "error", err)
	case res.Unchanged:
		// 304: cached set is current.
	default:
		h.Update(res.Generation, res.Hosts, res.Etag)
		slog.Info("edge: known-host set updated", "generation", res.Generation, "hosts", len(res.Hosts))
	}
}

// RunHostsRefresh runs the periodic known-host refresh forever. The first tick is
// jittered by [0,interval] (fleet poll-instant decorrelation); same cadence as
// the cert/WAF refresh; fail-static. poke (nil ok) wakes the loop on the
// /v1/events hosts change signal, so the timer is only the fallback floor.
func RunHostsRefresh(ctx context.Context, cp *CpClient, h *EdgeHosts, interval time.Duration, poke <-chan struct{}) {
	if interval <= 0 { // time.NewTicker panics on a non-positive interval
		interval = 300 * time.Second
	}
	runRefreshLoop(ctx, interval, poke, func() { RefreshHostsOnce(cp, h) })
}
