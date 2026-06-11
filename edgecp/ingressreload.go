package edgecp

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"time"

	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/k8s"
)

// IngressReloader derives the zone bindings from Ingress objects: for each
// Ingress carrying the `parapet.moonrhythm.io/waf-zone` annotation, every route
// pattern its rules register at the controller maps to the resolved zone key
// (PATH-AWARE — see buildZoneRoutes; the legacy host→zoneKey map is still
// derived for older edges). parapet re-runs the full WAF authoritatively
// regardless (see EDGE.md).
//
// With WithRateLimit it additionally derives, from the SAME Ingress list, the
// rate-limit bindings (`…/ratelimit-zone`, same-namespace only) and the
// known-host list the edge wires as its host-key collapser. store may be
// nil when only the rate-limit side is enabled.
type IngressReloader struct {
	store          *WafStore       // optional (nil = WAF host→zone derivation off)
	rl             *RateLimitStore // optional (nil = rate-limit derivation off)
	watchNamespace string
	debounce       time.Duration
}

func NewIngressReloader(store *WafStore, watchNamespace string) *IngressReloader {
	return &IngressReloader{store: store, watchNamespace: watchNamespace, debounce: 300 * time.Millisecond}
}

// WithRateLimit wires the rate-limit store so the Ingress reload also derives
// its host→zone binding and known-host list. Returns the reloader for chaining.
func (r *IngressReloader) WithRateLimit(rl *RateLimitStore) *IngressReloader {
	r.rl = rl
	return r
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
	if r.store != nil {
		r.store.SetIngressDerived(buildHostZone(ings), buildZoneRoutes(ings, WAFZoneAnnotation, false))
	}
	if r.rl != nil {
		r.rl.SetIngressDerived(buildRateLimitHostZone(ings), buildZoneRoutes(ings, RateLimitZoneAnnotation, true), collectIngressHosts(ings))
	}
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

// buildRateLimitHostZone maps each host of a ratelimit-zone-bound Ingress to
// its resolved zone key — SAME NAMESPACE ONLY, mirroring plugin.RateLimitZone:
// a rate-limit zone carries shared counter state, so a cross-namespace bind
// would let any tenant burn another tenant's per-key budgets. A cross-namespace
// reference is logged and ignored, exactly like the controller.
func buildRateLimitHostZone(ings []networking.Ingress) map[string]string {
	hz := map[string]string{}
	for i := range ings {
		ing := &ings[i]
		raw := ing.Annotations[RateLimitZoneAnnotation]
		key, ok := zoneKeyOf(ing.Namespace, raw)
		if !ok {
			continue
		}
		if !strings.HasPrefix(key, ing.Namespace+"/") {
			slog.Warn("edgecp: cross-namespace ratelimit-zone is not honored (zones carry shared counter state); ignoring",
				"ingress", ing.Namespace+"/"+ing.Name, "zone", key)
			continue
		}
		for _, rule := range ing.Spec.Rules {
			host := strings.ToLower(strings.TrimSpace(rule.Host))
			if host == "" {
				continue
			}
			hz[host] = key
		}
	}
	return hz
}

// collectIngressHosts returns every host declared by an Ingress rule
// (lowercased, deduped, sorted — the order feeds the store fingerprint). The
// edge wires this as the Limiter's KnownHost, so host-keyed limit buckets for
// hosts no Ingress declares collapse into one shared bucket — mirroring the
// controller's IsKnownHost cardinality bound under a random-Host flood.
func collectIngressHosts(ings []networking.Ingress) []string {
	seen := map[string]struct{}{}
	for i := range ings {
		for _, rule := range ings[i].Spec.Rules {
			host := strings.ToLower(strings.TrimSpace(rule.Host))
			if host == "" {
				continue
			}
			seen[host] = struct{}{}
		}
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// buildZoneRoutes maps each route pattern of a zone-bound Ingress to its
// resolved zone key. Patterns are byte-identical to the route keys the
// controller registers on its mux (Prefix → "host/path" + "host/path/", Exact →
// trailing slash stripped, ImplementationSpecific → as-is), so the edge — which
// loads them into a real http.ServeMux — resolves a request's zone exactly as
// the core does, including two ingresses sharing a host with different paths
// and different zones. Divergences from the controller's registration are
// deliberate: the CP doesn't watch Services, so routes the controller skips for
// a missing Service/port still get a binding here (the edge enforcing a zone on
// a route the core 404s is conservative); a host-less rule is skipped (it can't
// be scoped to an edge; the core remains authoritative for it); and an
// HTTP-less rule (host only, e.g. TLS-only) is skipped because the controller
// registers no route for it — the core never zone-evaluates that host, so
// binding it at the edge (as the legacy host-level map did) was
// over-enforcement, not parity.
//
// sameNamespaceOnly enforces the rate-limit zone posture (a zone carries shared
// counter state — see buildRateLimitHostZone); the WAF allows cross-namespace
// references, mirroring plugin.WAFZone.
//
// Identical patterns from different ingresses collide last-writer-wins, the
// same arbitrary resolution the controller's own routes map has — but unlike
// the host-level maps the collision surface is an exact host+path duplicate,
// not a whole host.
func buildZoneRoutes(ings []networking.Ingress, annotation string, sameNamespaceOnly bool) map[string]string {
	rz := map[string]string{}
	for i := range ings {
		ing := &ings[i]
		key, ok := zoneKeyOf(ing.Namespace, ing.Annotations[annotation])
		if !ok {
			continue
		}
		if sameNamespaceOnly && !strings.HasPrefix(key, ing.Namespace+"/") {
			// already warned by the host-level builder
			continue
		}
		for _, rule := range ing.Spec.Rules {
			host := strings.ToLower(strings.TrimSpace(rule.Host))
			if host == "" || rule.HTTP == nil {
				continue
			}
			for _, httpPath := range rule.HTTP.Paths {
				for _, pattern := range routePatterns(host, httpPath) {
					rz[pattern] = key
				}
			}
		}
	}
	return rz
}

// routePatterns mirrors the controller's route registration (controller.go,
// reloadDebounced's path switch) for one Ingress HTTP path.
func routePatterns(host string, httpPath networking.HTTPIngressPath) []string {
	path := httpPath.Path
	if path == "" { // path can not be empty
		path = "/"
	}
	if !strings.HasPrefix(path, "/") { // path must start with /
		path = "/" + path
	}
	pathType := networking.PathTypeImplementationSpecific
	if httpPath.PathType != nil {
		pathType = *httpPath.PathType
	}
	switch pathType {
	case networking.PathTypePrefix:
		src := host + strings.TrimSuffix(path, "/")
		var out []string
		if path != "/" {
			out = append(out, src)
		}
		return append(out, src+"/")
	case networking.PathTypeExact:
		src := host + strings.TrimSuffix(path, "/")
		if path == "/" { // exact root is registered as prefix by the controller
			src = host + path
		}
		return []string{src}
	default: // ImplementationSpecific
		return []string{host + path}
	}
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
