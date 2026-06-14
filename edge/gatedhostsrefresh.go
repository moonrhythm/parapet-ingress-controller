package edge

import (
	"context"
	"log/slog"
	"time"
)

// RefreshGatedHostsOnce fetches the forward-auth-gated host list (ETag-revalidated)
// and swaps it into EdgeGatedHosts. A fetch failure is fail-static — the edge
// keeps bypassing the cache for the hosts it already knows are gated. There is no
// compile step, so a 200 always applies.
func RefreshGatedHostsOnce(cp *CpClient, h *EdgeGatedHosts) {
	res, err := cp.FetchGatedHosts(h.Etag())
	switch {
	case err != nil:
		slog.Warn("edge: gated-hosts fetch failed; keeping last-good gated-host set", "error", err)
	case res.Unchanged:
		// 304: cached set is current.
	default:
		h.Update(res.Generation, res.Hosts, res.Etag)
		slog.Info("edge: gated-host set updated", "generation", res.Generation, "hosts", len(res.Hosts))
	}
}

// RunGatedHostsRefresh runs the periodic gated-host refresh forever. The first
// tick is jittered by [0,interval] (fleet poll-instant decorrelation); same
// cadence as the cert/WAF refresh; fail-static. poke (nil ok) wakes the loop on
// the /v1/events gated-hosts change signal, so the timer is only the fallback
// floor.
func RunGatedHostsRefresh(ctx context.Context, cp *CpClient, h *EdgeGatedHosts, interval time.Duration, poke <-chan struct{}) {
	if interval <= 0 { // time.NewTicker panics on a non-positive interval
		interval = 300 * time.Second
	}
	runRefreshLoop(ctx, interval, poke, func() { RefreshGatedHostsOnce(cp, h) })
}
