package edgecp

import (
	"context"
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
)

// RateLimitReloader keeps the RateLimitStore's limit sets in sync with the
// cluster's rate-limit ConfigMaps (label `parapet.moonrhythm.io/ratelimit`).
// Global limits are honored only from podNamespace; zone limits are collected
// from any watched namespace, keyed "<ns>/<name>". Same list-on-change pattern
// as the WafReloader.
type RateLimitReloader struct {
	store          *RateLimitStore
	watchNamespace string // "" = all namespaces (zones can live anywhere)
	podNamespace   string // bounds the global limit set
	debounce       time.Duration
}

func NewRateLimitReloader(store *RateLimitStore, watchNamespace, podNamespace string) *RateLimitReloader {
	return &RateLimitReloader{
		store:          store,
		watchNamespace: watchNamespace,
		podNamespace:   podNamespace,
		debounce:       300 * time.Millisecond,
	}
}

// LoadOnce does a single synchronous load. Call it before serving so the first
// edge fetch sees a populated store (same startup ordering as the WafReloader).
func (r *RateLimitReloader) LoadOnce(ctx context.Context) error { return r.reload(ctx) }

// Watch re-establishes the ConfigMap watch and reloads (debounced) on change.
// Blocks until ctx is cancelled; run it in a goroutine after LoadOnce.
func (r *RateLimitReloader) Watch(ctx context.Context) {
	for ctx.Err() == nil {
		w, err := k8s.WatchConfigMaps(ctx, r.watchNamespace, RateLimitLabelKey)
		if err != nil {
			slog.Error("edgecp: watch ratelimit configmaps failed; retrying", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		r.drain(ctx, w.ResultChan())
		w.Stop()
	}
}

func (r *RateLimitReloader) drain(ctx context.Context, ch <-chan watch.Event) {
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
				slog.Error("edgecp: ratelimit reload failed", "err", err)
			}
		}
	}
}

// reload lists rate-limit ConfigMaps across the watch namespace and rebuilds
// the global set (podNamespace only) and the zone registry (any namespace). A
// ConfigMap that also carries the WAF label is refused (one ConfigMap per
// feature, mirroring the controller: both reloaders would consume all its data
// values and the lenient YAML parsers cross-parse the other feature's
// documents to zero entries silently).
func (r *RateLimitReloader) reload(ctx context.Context) error {
	cms, err := k8s.GetConfigMaps(ctx, r.watchNamespace, RateLimitLabelKey)
	if err != nil {
		return err
	}
	projected := make([]wafConfigMap, 0, len(cms))
	for i := range cms {
		cm := &cms[i]
		role := cm.Labels[RateLimitLabelKey]
		if role == wafRoleGlobal || role == wafRoleZone {
			if _, alsoWAF := cm.Labels[WAFLabelKey]; alsoWAF {
				slog.Warn("edgecp: ignoring configmap that carries both the ratelimit and waf labels; use one configmap per feature",
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
	r.store.SetGlobal(collectGlobalLimitDocs(projected, r.podNamespace))
	zones := collectZoneLimitDocs(projected)
	r.store.SetZones(zones)
	slog.Info("edgecp: ratelimit store reloaded", "zones", len(zones))
	return nil
}
