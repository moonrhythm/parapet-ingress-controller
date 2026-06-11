package edgecp

import (
	"context"
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
)

// WafReloader keeps the WafStore's rulesets in sync with the cluster's WAF
// ConfigMaps (label `parapet.moonrhythm.io/waf`). Global rules are honored only
// from podNamespace (the platform baseline boundary); zone rules are collected
// from any watched namespace, keyed "<ns>/<name>". Same list-on-change pattern
// as the cert Reloader.
type WafReloader struct {
	store          *WafStore
	watchNamespace string // "" = all namespaces (zones can live anywhere)
	podNamespace   string // bounds the global ruleset
	debounce       time.Duration
}

func NewWafReloader(store *WafStore, watchNamespace, podNamespace string) *WafReloader {
	return &WafReloader{
		store:          store,
		watchNamespace: watchNamespace,
		podNamespace:   podNamespace,
		debounce:       300 * time.Millisecond,
	}
}

// LoadOnce does a single synchronous load. Call it before serving so the first
// edge fetch sees a populated store (avoids a startup race where an edge caches
// an empty ruleset until the next refresh).
func (r *WafReloader) LoadOnce(ctx context.Context) error { return r.reload(ctx) }

// Watch relists on every (re)connect (see watchAndRelist) and reloads
// (debounced) on change. Blocks until ctx is cancelled; run it in a goroutine
// after LoadOnce.
func (r *WafReloader) Watch(ctx context.Context) {
	watchAndRelist(ctx, "waf configmaps",
		func(ctx context.Context) (watch.Interface, error) {
			return k8s.WatchConfigMaps(ctx, r.watchNamespace, WAFLabelKey)
		},
		r.reload, r.drain)
}

func (r *WafReloader) drain(ctx context.Context, ch <-chan watch.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ch:
			if !ok {
				return
			}
			timer := time.NewTimer(r.debounce)
		coalesce:
			for {
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case _, ok := <-ch:
					if !ok {
						timer.Stop()
						break coalesce
					}
					if !timer.Stop() {
						<-timer.C
					}
					timer.Reset(r.debounce)
				case <-timer.C:
					break coalesce
				}
			}
			if err := r.reload(ctx); err != nil {
				slog.Error("edgecp: waf reload failed", "err", err)
			}
		}
	}
}

// reload lists WAF ConfigMaps across the watch namespace and rebuilds the global
// ruleset (podNamespace only) and the zone registry (any namespace).
func (r *WafReloader) reload(ctx context.Context) error {
	cms, err := k8s.GetConfigMaps(ctx, r.watchNamespace, WAFLabelKey)
	if err != nil {
		return err
	}
	projected := make([]wafConfigMap, 0, len(cms))
	for i := range cms {
		cm := &cms[i]
		projected = append(projected, wafConfigMap{
			namespace: cm.Namespace,
			name:      cm.Name,
			labels:    cm.Labels,
			data:      cm.Data,
		})
	}
	r.store.SetGlobal(concatGlobalRules(projected, r.podNamespace))
	zones := collectZoneRules(projected)
	r.store.SetZones(zones)
	slog.Info("edgecp: waf store reloaded", "zones", len(zones))
	return nil
}
