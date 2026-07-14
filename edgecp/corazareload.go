package edgecp

import (
	"context"
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
)

// CorazaReloader keeps the CorazaStore's rulesets in sync with the cluster's
// Coraza ConfigMaps (label `parapet.moonrhythm.io/coraza`). Global rules are
// honored only from podNamespace (the platform baseline boundary); zone rules are
// collected from any watched namespace, keyed "<ns>/<name>". Mirrors WafReloader.
type CorazaReloader struct {
	store          *CorazaStore
	watchNamespace string
	podNamespace   string
	debounce       time.Duration
}

func NewCorazaReloader(store *CorazaStore, watchNamespace, podNamespace string) *CorazaReloader {
	return &CorazaReloader{
		store:          store,
		watchNamespace: watchNamespace,
		podNamespace:   podNamespace,
		debounce:       300 * time.Millisecond,
	}
}

// LoadOnce does a single synchronous load. Call it before serving so the first
// edge fetch sees a populated store.
func (r *CorazaReloader) LoadOnce(ctx context.Context) error { return r.reload(ctx) }

// Watch relists on every (re)connect and reloads (debounced) on change. Blocks
// until ctx is cancelled; run it in a goroutine after LoadOnce.
func (r *CorazaReloader) Watch(ctx context.Context) {
	watchAndRelist(ctx, "coraza configmaps",
		func(ctx context.Context) (watch.Interface, error) {
			return k8s.WatchConfigMaps(ctx, r.watchNamespace, CorazaLabelKey)
		},
		r.reload, r.drain)
}

func (r *CorazaReloader) drain(ctx context.Context, ch <-chan watch.Event) {
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
				slog.Error("edgecp: coraza reload failed", "err", err)
			}
		}
	}
}

// reload lists Coraza ConfigMaps across the watch namespace and rebuilds the
// global ruleset (podNamespace only) and the zone registry (any namespace). A
// ConfigMap that also carries another feature's label is refused (one ConfigMap
// per feature, mirroring the controller: the edge's lenient YAML parsers would
// cross-parse the other feature's documents to zero entries silently).
func (r *CorazaReloader) reload(ctx context.Context) error {
	cms, err := k8s.GetConfigMaps(ctx, r.watchNamespace, CorazaLabelKey)
	if err != nil {
		return err
	}
	projected := make([]wafConfigMap, 0, len(cms))
	for i := range cms {
		cm := &cms[i]
		role := cm.Labels[CorazaLabelKey]
		if role == corazaRoleGlobal || role == corazaRoleZone {
			if other, ok := carriesOtherFeatureLabel(cm.Labels, CorazaLabelKey); ok {
				slog.Warn("edgecp: ignoring configmap that carries the coraza label and another feature label; use one configmap per feature",
					"configmap", cm.Namespace+"/"+cm.Name, "other_label", other)
				continue
			}
		}
		projected = append(projected, wafConfigMap{
			namespace: cm.Namespace,
			name:      cm.Name,
			labels:    cm.Labels,
			data:      cm.Data,
		})
	}
	r.store.SetGlobal(concatGlobalCorazaRules(projected, r.podNamespace))
	zones := collectCorazaZoneRules(projected)
	r.store.SetZones(zones)
	slog.Info("edgecp: coraza store reloaded", "zones", len(zones))
	return nil
}
