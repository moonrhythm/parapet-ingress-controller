package edgecp

import (
	"context"
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
)

// CacheReloader keeps the CacheStore's override sets in sync with the cluster's
// cache ConfigMaps (label `parapet.moonrhythm.io/cache`). Global overrides are
// honored only from podNamespace; zone overrides are collected from any watched
// namespace, keyed "<ns>/<name>". Same list-on-change pattern as the
// WafReloader / RateLimitReloader.
type CacheReloader struct {
	store          *CacheStore
	watchNamespace string // "" = all namespaces (zones can live anywhere)
	podNamespace   string // bounds the global override set
	debounce       time.Duration
}

func NewCacheReloader(store *CacheStore, watchNamespace, podNamespace string) *CacheReloader {
	return &CacheReloader{
		store:          store,
		watchNamespace: watchNamespace,
		podNamespace:   podNamespace,
		debounce:       300 * time.Millisecond,
	}
}

// LoadOnce does a single synchronous load. Call it before serving so the first
// edge fetch sees a populated store.
func (r *CacheReloader) LoadOnce(ctx context.Context) error { return r.reload(ctx) }

// Watch relists on every (re)connect (see watchAndRelist) and reloads
// (debounced) on change. Blocks until ctx is cancelled; run it in a goroutine
// after LoadOnce.
func (r *CacheReloader) Watch(ctx context.Context) {
	watchAndRelist(ctx, "cache configmaps",
		func(ctx context.Context) (watch.Interface, error) {
			return k8s.WatchConfigMaps(ctx, r.watchNamespace, CacheLabelKey)
		},
		r.reload, r.drain)
}

func (r *CacheReloader) drain(ctx context.Context, ch <-chan watch.Event) {
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
				slog.Error("edgecp: cache reload failed", "err", err)
			}
		}
	}
}

// reload lists cache ConfigMaps across the watch namespace and rebuilds the
// global set (podNamespace only) and the zone registry (any namespace). A
// ConfigMap that also carries the WAF or rate-limit label is refused (one
// ConfigMap per feature, mirroring the controller and the other reloaders: the
// lenient YAML parsers would cross-parse the other feature's documents to zero
// entries silently).
func (r *CacheReloader) reload(ctx context.Context) error {
	cms, err := k8s.GetConfigMaps(ctx, r.watchNamespace, CacheLabelKey)
	if err != nil {
		return err
	}
	projected := make([]wafConfigMap, 0, len(cms))
	for i := range cms {
		cm := &cms[i]
		role := cm.Labels[CacheLabelKey]
		if role == wafRoleGlobal || role == wafRoleZone {
			if _, alsoWAF := cm.Labels[WAFLabelKey]; alsoWAF {
				slog.Warn("edgecp: ignoring configmap that carries both the cache and waf labels; use one configmap per feature",
					"configmap", cm.Namespace+"/"+cm.Name)
				continue
			}
			if _, alsoRL := cm.Labels[RateLimitLabelKey]; alsoRL {
				slog.Warn("edgecp: ignoring configmap that carries both the cache and ratelimit labels; use one configmap per feature",
					"configmap", cm.Namespace+"/"+cm.Name)
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
	r.store.SetGlobal(collectGlobalCacheDocs(projected, r.podNamespace))
	zones := collectZoneCacheDocs(projected)
	r.store.SetZones(zones)
	slog.Info("edgecp: cache store reloaded", "zones", len(zones))
	return nil
}
