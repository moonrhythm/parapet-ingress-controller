package edge

import (
	"bytes"
	"context"
	"log/slog"
	"time"

	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/common/expfmt"
)

// PushMetricsOnce gathers the FULL shared registry (parapet request/host/backend
// vecs + the edge_* convergence gauges + go_*/process_*) as one text-exposition
// snapshot and pushes it to the control plane. The CP injects the authoritative
// edge_id (from the bearer token) and the edge_instance label, so what's gathered
// here never needs to self-label. Fail-static: an error leaves the CP serving the
// previous snapshot until it TTL-expires; the next tick pushes a complete fresh one.
func PushMetricsOnce(cp *CpClient, instance string) error {
	mfs, err := prom.Registry().Gather()
	if err != nil && len(mfs) == 0 {
		metricsPush("gather_fail")
		return err
	}
	format := expfmt.NewFormat(expfmt.TypeTextPlain)
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, format)
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			metricsPush("gather_fail")
			return err
		}
	}
	if err := cp.PushMetrics(instance, string(format), buf.Bytes()); err != nil {
		metricsPush("push_fail")
		return err
	}
	metricsPush("ok")
	return nil
}

// RunMetricsPush pushes the registry to the control plane every interval, forever.
// The first tick is jittered by [0,interval] to decorrelate the fleet's push
// instants. Failures are logged + counted and the loop keeps going (fail-static —
// the CP serves the last-good snapshot until its TTL).
func RunMetricsPush(ctx context.Context, cp *CpClient, instance string, interval time.Duration) {
	if interval <= 0 { // time.NewTicker panics on a non-positive interval
		interval = 60 * time.Second
	}
	if !sleepCtx(ctx, fullJitter(interval)) {
		return
	}
	// Push once right after the jitter so the CP has fleet data within ONE interval
	// of boot (the ticker alone would delay the first snapshot to jitter+interval).
	if err := PushMetricsOnce(cp, instance); err != nil {
		slog.Warn("edge: metrics push failed; control plane keeps last snapshot until TTL", "error", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := PushMetricsOnce(cp, instance); err != nil {
				slog.Warn("edge: metrics push failed; control plane keeps last snapshot until TTL", "error", err)
			}
		}
	}
}
