package edge

import (
	"context"
	"log/slog"
	"time"
)

// RefreshTopologyOnce fetches the unified topology (ETag-revalidated) and swaps
// it into the EdgeTopology. A fetch failure is fail-static — the edge keeps its
// last-good bindings + known-host set and never falls back to "no topology"
// (which would unbind every zone and collapse every host). There is no compile
// step, so a 200 always applies.
func RefreshTopologyOnce(cp *CpClient, t *EdgeTopology) {
	res, err := cp.FetchTopology(t.Etag())
	switch {
	case err != nil:
		slog.Warn("edge: topology fetch failed; keeping last-good bindings", "error", err)
	case res.Unchanged:
		// 304: cached topology is current.
	default:
		t.Update(res.Generation, res.WAFRouteZone, res.WAFHostZone, res.RLRouteZone, res.RLHostZone, res.Hosts, res.Etag)
		slog.Info("edge: topology updated", "generation", res.Generation, "hosts", len(res.Hosts))
	}
}

// RunTopologyRefresh runs the periodic topology refresh forever. The first tick
// is jittered by [0,interval] (fleet poll-instant decorrelation); same cadence
// as the cert/WAF refresh; fail-static. poke (nil ok) wakes the loop immediately
// on the /v1/events topology change signal, so the timer is only the fallback
// floor. All refreshes run on THIS goroutine, keeping them single-flight.
func RunTopologyRefresh(ctx context.Context, cp *CpClient, t *EdgeTopology, interval time.Duration, poke <-chan struct{}) {
	if interval <= 0 { // time.NewTicker panics on a non-positive interval
		interval = 300 * time.Second
	}
	runRefreshLoop(ctx, interval, poke, func() { RefreshTopologyOnce(cp, t) })
}
