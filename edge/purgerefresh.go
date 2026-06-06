package edge

import (
	"context"
	"log/slog"
	"time"
)

// RefreshPurgeOnce polls the control plane for cache-purge directives and applies
// them to the table. Fail-static: a fetch error keeps the table's applied epochs +
// cursor untouched (pending purges are delayed, not lost — the journal+cursor catch
// up on the next poll). A flush_required (the edge fell behind the CP's retained
// journal) bumps the global epoch and jumps the cursor; otherwise new entries are
// applied idempotently. A 404 (purge distribution disabled at the CP) is a quiet
// no-op.
func RefreshPurgeOnce(cp *CpClient, table *PurgeTable) {
	res, err := cp.FetchPurges(table.Cursor())
	switch {
	case err != nil:
		slog.Warn("edge: purge poll failed; keeping applied epochs", "error", err)
		purgePoll("error")
		return
	case res.Disabled:
		// CP isn't distributing purges; nothing to do.
		purgePoll("disabled")
		return
	case res.FlushRequired || res.MaxSeq < table.Cursor():
		// FlushRequired: the CP signalled a gap or a journal reset (our cursor is ahead
		// of its lastSeq). The MaxSeq < cursor guard is defense-in-depth for an OLDER CP
		// that predates the cursor-ahead-of-journal check (independent edge/CP rollout) —
		// it would otherwise return flush_required=false on a reset and silently
		// under-invalidate. FlushAll realigns the cursor (down, if needed) to MaxSeq.
		if err := table.FlushAll(res.MaxSeq); err != nil {
			slog.Warn("edge: purge state persist failed after flush; in-memory state applied", "error", err)
		}
		slog.Info("edge: cache purge flush-all", "max_seq", res.MaxSeq, "flush_required", res.FlushRequired)
		purgePoll("flush")
	default:
		if len(res.Entries) > 0 {
			slog.Info("edge: cache purges applied", "count", len(res.Entries), "max_seq", res.MaxSeq)
		}
		if err := table.Apply(res.Entries, res.MaxSeq); err != nil {
			slog.Warn("edge: purge state persist failed; in-memory state applied", "error", err)
		}
		purgePollApplied(len(res.Entries))
		purgePoll("ok")
	}
	setPurgeMetrics(table.Stats())
}

// RunPurgeRefresh runs the periodic cache-purge poll forever. The first tick is
// jittered by [0,interval] to decorrelate the fleet's poll instants. The cadence is
// independent of (and typically faster than) the cert/WAF refresh, since purge
// latency is operator-facing. Fail-static.
func RunPurgeRefresh(ctx context.Context, cp *CpClient, table *PurgeTable, interval time.Duration) {
	if interval <= 0 { // time.NewTicker panics on a non-positive interval
		interval = 10 * time.Second
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
			RefreshPurgeOnce(cp, table)
		}
	}
}
