package edgecp

import (
	"context"
	"log/slog"
	"strings"
	"time"

	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/go/k8s"
)

// IngressReloader derives the host→zoneKey binding from Ingress objects: for each
// Ingress carrying the `parapet.moonrhythm.io/waf-zone` annotation, every host in
// its rules maps to the resolved zone key. This is host-level (not host/path) —
// the edge applies a zone per host as an early-drop layer; parapet re-runs the
// full WAF with path-precise zone resolution authoritatively (see EDGE.md).
type IngressReloader struct {
	store          *WafStore
	watchNamespace string
	debounce       time.Duration
}

func NewIngressReloader(store *WafStore, watchNamespace string) *IngressReloader {
	return &IngressReloader{store: store, watchNamespace: watchNamespace, debounce: 300 * time.Millisecond}
}

// LoadOnce does a single synchronous load (call before serving — see WafReloader).
func (r *IngressReloader) LoadOnce(ctx context.Context) error { return r.reload(ctx) }

// Watch re-establishes the Ingress watch and reloads on change. Run after LoadOnce.
func (r *IngressReloader) Watch(ctx context.Context) {
	for ctx.Err() == nil {
		w, err := k8s.WatchIngresses(ctx, r.watchNamespace)
		if err != nil {
			slog.Error("edgecp: watch ingresses failed; retrying", "err", err)
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

func (r *IngressReloader) drain(ctx context.Context, ch <-chan watch.Event) {
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
				slog.Error("edgecp: ingress reload failed", "err", err)
			}
		}
	}
}

func (r *IngressReloader) reload(ctx context.Context) error {
	ings, err := k8s.GetIngresses(ctx, r.watchNamespace)
	if err != nil {
		return err
	}
	r.store.SetHostZone(buildHostZone(ings))
	return nil
}

// buildHostZone maps each host of a zone-bound Ingress to its resolved zone key.
// Last writer wins on host collisions (rare; matches the controller's
// last-reconciled behavior). Hosts are lowercased to match SNI normalization.
func buildHostZone(ings []networking.Ingress) map[string]string {
	hz := map[string]string{}
	for i := range ings {
		ing := &ings[i]
		raw := ing.Annotations[WAFZoneAnnotation]
		key, ok := zoneKeyOf(ing.Namespace, raw)
		if !ok {
			continue
		}
		for _, rule := range ing.Spec.Rules {
			host := strings.ToLower(strings.TrimSpace(rule.Host))
			if host == "" {
				continue // a host-less rule can't be SNI-routed at the edge
			}
			hz[host] = key
		}
	}
	return hz
}

// zoneKeyOf mirrors the controller's plugin.ZoneKey / resolve_zone_key: a bare id
// uses the ingress namespace; "ns/id" is verbatim; empty/malformed → not ok.
func zoneKeyOf(ingressNamespace, annotation string) (string, bool) {
	v := strings.TrimSpace(annotation)
	if v == "" {
		return "", false
	}
	if i := strings.IndexByte(v, '/'); i >= 0 {
		ns := strings.TrimSpace(v[:i])
		name := strings.TrimSpace(v[i+1:])
		if ns == "" || name == "" || strings.Contains(name, "/") {
			return "", false
		}
		return ns + "/" + name, true
	}
	return ingressNamespace + "/" + v, true
}
