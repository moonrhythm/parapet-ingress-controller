package edge

import (
	"context"
	"log/slog"
	"time"

	"github.com/moonrhythm/parapet/pkg/cache"
)

// ReapOnce sweeps the cache storage once, PHYSICALLY deleting every entry the
// purge table has invalidated (Meta.Created <= the entry's invalidation epoch).
//
// It complements the lazy lookup gate (PurgeTable.InvalidatedAfter): the gate
// reaps an entry only when it is next looked up, so after a broad purge with
// little subsequent traffic the now-dead bytes would linger until LRU pressure
// evicts them. The reaper reclaims them proactively. Correctness never depends on
// it — the gate already guarantees a purged entry is never served — it is purely
// reclamation, and over-deleting a still-valid entry (e.g. a Created stamped low
// by a wall-clock step) only costs a re-fetch, never a stale serve.
//
// The reaper deliberately does NOT retire purge records: that is the one
// under-invalidating direction, and it cannot be made safe against a backward
// wall-clock step between a purge and a later fill's commit (both Meta.Created and
// the sweep marker are unclamped wall clocks). The in-memory table is instead
// bounded by the monotonic, over-invalidating count-cap fold (enforceCapLocked) —
// see PurgeTable. Purges are operator-issued, so the maps stay small regardless.
func ReapOnce(storage cache.Storage, table *PurgeTable) {
	reaped := table.Reap(storage)
	if reaped > 0 {
		slog.Info("edge: cache reaper swept invalidated entries", "reaped", reaped)
	}
	purgeReap(reaped)
	setPurgeMetrics(table.Stats())
}

// RunReaper runs the periodic cache reaper forever. The first tick is jittered by
// [0,interval] to decorrelate the fleet. The cadence (EDGE_CACHE_PURGE_SWEEP_INTERVAL)
// is independent of the purge poll — it is housekeeping, not latency-sensitive.
func RunReaper(ctx context.Context, storage cache.Storage, table *PurgeTable, interval time.Duration) {
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
			ReapOnce(storage, table)
		}
	}
}
