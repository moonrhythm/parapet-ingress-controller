package controller

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/healthz"
	"github.com/moonrhythm/parapet/pkg/waf"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/moonrhythm/parapet-ingress-controller/cert"
	"github.com/moonrhythm/parapet-ingress-controller/corazawaf"
	"github.com/moonrhythm/parapet-ingress-controller/debounce"
	"github.com/moonrhythm/parapet-ingress-controller/k8s"
	"github.com/moonrhythm/parapet-ingress-controller/metric"
	"github.com/moonrhythm/parapet-ingress-controller/plugin"
	"github.com/moonrhythm/parapet-ingress-controller/proxy"
	"github.com/moonrhythm/parapet-ingress-controller/ratelimitrule"
	"github.com/moonrhythm/parapet-ingress-controller/route"
	"github.com/moonrhythm/parapet-ingress-controller/state"
)

// IngressClass to load ingresses
var IngressClass = "parapet"

const (
	routeSizeHint    = 500
	endpointSizeHint = 500
	secretSizeHint   = 50
)

// routeState is the immutable routing snapshot swapped in on each ingress
// reload: the live mux plus the set of hosts it serves. Bundling both behind one
// atomic.Pointer lets the request path read them with a single lock-free load
// instead of taking a per-request RWMutex. knownHosts bounds host-labeled metric
// cardinality — a Host the router doesn't serve collapses to a sentinel label
// instead of minting unbounded series under a random-Host flood.
type routeState struct {
	mux        *http.ServeMux
	knownHosts map[string]struct{}
}

// Controller is the parapet ingress controller
type Controller struct {
	// routes is the current routing snapshot, swapped atomically on reload so the
	// request path (ServeHandler, IsKnownHost) reads it lock-free. Never nil after
	// New(); reloadIngressDebounced builds a fresh *routeState and Stores it.
	routes atomic.Pointer[routeState]

	// namespace to watch, or empty to watch all
	watchNamespace string

	// LoadAllCerts, when true, builds the cert table from every TLS-typed
	// secret in the watch namespace instead of only those referenced by an
	// Ingress's spec.tls.secretName. The cert table already does SNI lookup
	// with wildcard climbing, so enabling this lets a wildcard cert serve any
	// matching subdomain without the user (or operator) having to wire the
	// matching secret into each ingress. Off by default to preserve behavior.
	LoadAllCerts bool

	// WAFConfig configures the web application firewall; PodNamespace is the
	// controller's own namespace, which bounds where the global ruleset may be
	// defined. Both are set before Watch(). See controller_waf.go.
	WAFConfig    WAFConfig
	PodNamespace string

	// WaitTrustReady, when set (edge auto-trust enabled), is invoked by firstReload
	// just before the controller reports Ready. It blocks until the edge-CA pool has
	// loaded — bounded, with a fail-static deadline fallback — so the edge's first
	// connections aren't established during the cold-start window (when the :443 config
	// sends no CertificateRequest and the connection would stay CIDR-only, i.e.
	// untrusted for a mTLS-only edge, until it recycles). It MUST return on its own
	// deadline even if the pool never loads: the trust CP is an optional overlay and
	// must never gate serving. Installed by main before Watch(); nil (skipped) when
	// auto-trust is off. See trust.Manager.WaitReady.
	WaitTrustReady func()

	// RateLimitConfig configures the ConfigMap-driven rate limiting (global +
	// zone sets, mirroring the WAF model). Set before Watch(); when disabled the
	// feature does no work: no ConfigMap watch, no mount. See
	// controller_ratelimit.go.
	RateLimitConfig RateLimitConfig

	// CorazaConfig configures the Coraza (OWASP CRS / SecLang) firewall — an
	// independent signature layer alongside the CEL WAF, with the same global +
	// zone model. Set before Watch(); when disabled the feature does no work. See
	// controller_coraza.go.
	CorazaConfig CorazaConfig

	// globalWAF is the always-on baseline firewall; zones holds the tenant zone
	// registry keyed by <namespace>/<name>, swapped atomically on WAF reload.
	// WAF reloads are decoupled from the mux — they never rebuild routes.
	globalWAF *waf.WAF
	zones     atomic.Pointer[map[string]*waf.WAF]

	// globalRateLimit is the baseline rate-limit set; rlZones holds the tenant
	// zone registry keyed by <namespace>/<name>, swapped atomically on rate-limit
	// reload. Decoupled from the mux exactly like the WAF registries.
	globalRateLimit *ratelimitrule.Limiter
	rlZones         atomic.Pointer[map[string]*ratelimitrule.Limiter]

	// globalCoraza is the baseline Coraza (SecLang/CRS) firewall; corazaZones
	// holds the tenant zone registry keyed by <namespace>/<name>, swapped
	// atomically on Coraza reload. Decoupled from the mux like the WAF registries.
	globalCoraza *corazawaf.Instance
	corazaZones  atomic.Pointer[map[string]*corazawaf.Instance]

	// WAF rule-input fingerprints from the last reload, used to skip recompiling
	// CEL rulesets whose effective input (the sorted concatenated rule YAML) is
	// byte-for-byte unchanged. These are read/written only from reloadWAFDebounced,
	// but the debounce does NOT guarantee single-flight execution (a timer-fired
	// run executes in its own goroutine without the debounce lock, and an
	// already-fired Timer.Stop is a no-op), so two reloadWAFDebounced passes can
	// overlap under rapid ConfigMap churn when one pass outlives the debounce
	// window. wafReloadMu serializes the whole pass so the fingerprint string and
	// map are never raced (a concurrent map read/write is an unrecoverable fatal).
	wafReloadMu          sync.Mutex
	globalWAFFingerprint string
	zoneFingerprints     map[string]string

	// Rate-limit reload state, the exact mirror of the WAF fields above —
	// rlReloadMu serializes overlapping debounce-fired passes, the fingerprints
	// skip reapplying unchanged input (which for rate limits also preserves live
	// counters). Accessed only under rlReloadMu.
	rlReloadMu          sync.Mutex
	globalRLFingerprint string
	rlZoneFingerprints  map[string]string

	// Coraza reload state, the exact mirror of the WAF fields above —
	// corazaReloadMu serializes overlapping debounce-fired passes, the
	// fingerprints skip recompiling unchanged SecLang input. Accessed only under
	// corazaReloadMu.
	corazaReloadMu          sync.Mutex
	globalCorazaFingerprint string
	corazaZoneFingerprints  map[string]string

	// endpointReloadMu serializes host-route recomputes. Two watch goroutines now
	// feed pod IPs — the EndpointSlice watch and the legacy-Endpoints fallback
	// watch — and both compute a Service's host route by reading the slice +
	// endpoints stores and then SetHostRoute. Without serialization, one
	// goroutine could read a now-stale "slice present" state and write its result
	// after the other goroutine wrote the fresh "slice gone → fallback" result,
	// clobbering it. Holding this across read+write makes the last writer also the
	// latest reader, so the route always reflects the current store state.
	endpointReloadMu sync.Mutex

	// holds current k8s state
	watchedIngresses        sync.Map
	watchedServices         sync.Map
	watchedSecrets          sync.Map
	watchedEndpointSlices   sync.Map
	watchedEndpoints        sync.Map // legacy fallback: only used for services with no EndpointSlice
	watchedConfigMaps       sync.Map
	watchedRLConfigMaps     sync.Map
	watchedCorazaConfigMaps sync.Map

	certTable  cert.Table
	routeTable route.Table

	proxy *proxy.Proxy

	plugins []plugin.Plugin
	health  *healthz.Healthz

	reloadIngressDebounce   *debounce.Debounce
	reloadServiceDebounce   *debounce.Debounce
	reloadSecretDebounce    *debounce.Debounce
	reloadWAFDebounce       *debounce.Debounce
	reloadRateLimitDebounce *debounce.Debounce
	reloadCorazaDebounce    *debounce.Debounce
}

// New creates new ingress controller
func New(watchNamespace string, proxy *proxy.Proxy) *Controller {
	ctrl := &Controller{}
	// Seed an empty routing snapshot so the request path never observes a nil
	// pointer if a request lands before the first reload completes.
	ctrl.routes.Store(&routeState{mux: http.NewServeMux(), knownHosts: map[string]struct{}{}})
	ctrl.health = healthz.New()
	ctrl.health.SetReady(false)
	ctrl.watchNamespace = watchNamespace
	ctrl.reloadIngressDebounce = debounce.New(ctrl.reloadIngressDebounced, 300*time.Millisecond)
	ctrl.reloadServiceDebounce = debounce.New(ctrl.reloadServiceDebounced, 300*time.Millisecond)
	ctrl.reloadSecretDebounce = debounce.New(ctrl.reloadSecretDebounced, 300*time.Millisecond)
	ctrl.reloadWAFDebounce = debounce.New(ctrl.reloadWAFDebounced, 300*time.Millisecond)
	ctrl.reloadRateLimitDebounce = debounce.New(ctrl.reloadRateLimitDebounced, 300*time.Millisecond)
	ctrl.reloadCorazaDebounce = debounce.New(ctrl.reloadCorazaDebounced, 300*time.Millisecond)
	ctrl.proxy = proxy
	ctrl.proxy.OnDialError = ctrl.routeTable.MarkBad
	return ctrl
}

// Use appends a plugin
func (ctrl *Controller) Use(m plugin.Plugin) {
	ctrl.plugins = append(ctrl.plugins, m)
}

// ServeHandler implements parapet.Middleware
func (ctrl *Controller) ServeHandler(_ http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctrl.routes.Load().mux.ServeHTTP(w, r)
	})
}

// Watch starts watch k8s resource
func (ctrl *Controller) Watch() {
	ctx := context.Background()

	ctrl.preloadResources(ctx)
	ctrl.firstReload()

	go ctrl.watchIngresses(ctx)
	go ctrl.watchServices(ctx)
	go ctrl.watchSecrets(ctx)
	go ctrl.watchEndpointSlices(ctx)
	go ctrl.watchEndpoints(ctx)
	if ctrl.WAFConfig.Enabled {
		go ctrl.watchConfigMaps(ctx)
	}
	if ctrl.RateLimitConfig.Enabled {
		go ctrl.watchRateLimitConfigMaps(ctx)
	}
	if ctrl.CorazaConfig.Enabled {
		go ctrl.watchCorazaConfigMaps(ctx)
	}
}

// preloadResources lists every watched resource into the store before the first
// reload. Each list is RETRIED until it succeeds (or ctx is cancelled): the very
// next step (firstReload) flips the controller to Ready, so listing an empty store
// because the API server was momentarily unreachable would make the pod report
// healthy while serving 404 for every route. A legitimately empty namespace lists
// successfully (no error) and proceeds immediately.
func (ctrl *Controller) preloadResources(ctx context.Context) {
	preloadList(ctx, "ingresses", func() error {
		ingresses, err := k8s.GetIngresses(ctx, ctrl.watchNamespace)
		if err != nil {
			return err
		}
		for i := range ingresses {
			ctrl.watchedIngresses.Store(ingresses[i].Namespace+"/"+ingresses[i].Name, &ingresses[i])
		}
		return nil
	})
	preloadList(ctx, "services", func() error {
		services, err := k8s.GetServices(ctx, ctrl.watchNamespace)
		if err != nil {
			return err
		}
		for i := range services {
			ctrl.watchedServices.Store(services[i].Namespace+"/"+services[i].Name, &services[i])
		}
		return nil
	})
	preloadList(ctx, "secrets", func() error {
		secrets, err := k8s.GetSecrets(ctx, ctrl.watchNamespace)
		if err != nil {
			return err
		}
		for i := range secrets {
			ctrl.watchedSecrets.Store(secrets[i].Namespace+"/"+secrets[i].Name, &secrets[i])
		}
		return nil
	})
	preloadList(ctx, "endpointslices", func() error {
		slices, err := k8s.GetEndpointSlices(ctx, ctrl.watchNamespace)
		if err != nil {
			return err
		}
		for i := range slices {
			ctrl.watchedEndpointSlices.Store(slices[i].Namespace+"/"+slices[i].Name, &slices[i])
		}
		return nil
	})
	preloadList(ctx, "endpoints", func() error {
		endpoints, err := k8s.GetEndpoints(ctx, ctrl.watchNamespace)
		if err != nil {
			return err
		}
		for i := range endpoints {
			ctrl.watchedEndpoints.Store(endpoints[i].Namespace+"/"+endpoints[i].Name, &endpoints[i])
		}
		return nil
	})

	if ctrl.WAFConfig.Enabled {
		preloadList(ctx, "configmaps", func() error {
			configmaps, err := k8s.GetConfigMaps(ctx, ctrl.watchNamespace, wafLabelKey)
			if err != nil {
				return err
			}
			for i := range configmaps {
				ctrl.watchedConfigMaps.Store(configmaps[i].Namespace+"/"+configmaps[i].Name, &configmaps[i])
			}
			return nil
		})
	}

	if ctrl.RateLimitConfig.Enabled {
		preloadList(ctx, "ratelimit-configmaps", func() error {
			configmaps, err := k8s.GetConfigMaps(ctx, ctrl.watchNamespace, rateLimitLabelKey)
			if err != nil {
				return err
			}
			for i := range configmaps {
				ctrl.watchedRLConfigMaps.Store(configmaps[i].Namespace+"/"+configmaps[i].Name, &configmaps[i])
			}
			return nil
		})
	}

	if ctrl.CorazaConfig.Enabled {
		preloadList(ctx, "coraza-configmaps", func() error {
			configmaps, err := k8s.GetConfigMaps(ctx, ctrl.watchNamespace, corazaLabelKey)
			if err != nil {
				return err
			}
			for i := range configmaps {
				ctrl.watchedCorazaConfigMaps.Store(configmaps[i].Namespace+"/"+configmaps[i].Name, &configmaps[i])
			}
			return nil
		})
	}
}

// preloadList runs fn, retrying with capped exponential backoff on error until it
// succeeds or ctx is cancelled. The controller stays NotReady (firstReload hasn't
// run) for the duration, so a transient API-server outage at startup never lets it
// serve traffic with an empty route table.
func preloadList(ctx context.Context, name string, fn func() error) {
	const (
		baseBackoff = 500 * time.Millisecond
		maxBackoff  = 10 * time.Second
	)
	backoff := baseBackoff
	for {
		if err := fn(); err == nil {
			return
		} else {
			slog.Error("controller: preload failed; retrying (staying NotReady)", "resource", name, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func (ctrl *Controller) firstReload() {
	ctrl.reloadServiceDebounced()
	ctrl.reloadIngressDebounced()
	ctrl.reloadSecretDebounced()
	ctrl.reloadEndpointDebounced()
	ctrl.reloadWAFDebounced()       // no-op when WAF disabled
	ctrl.reloadRateLimitDebounced() // no-op when rate limiting disabled
	ctrl.reloadCorazaDebounced()    // no-op when Coraza disabled

	// Edge auto-trust: bounded wait for the edge-CA pool before reporting Ready, so the
	// edge isn't routed here during the cold-start window. Runs AFTER preload (above), so
	// the parallel trust fetch has had the whole preload to land — usually it already
	// has, making this a no-op. Fail-static: WaitTrustReady returns on its own deadline
	// even if the pool never loads, so a CP outage at boot never blocks serving.
	if ctrl.WaitTrustReady != nil {
		ctrl.WaitTrustReady()
	}

	// ready to serve requests
	ctrl.health.SetReady(true)
}

// watchResource runs a resilient watch loop for a single Kubernetes resource
// type: it (re)starts the watch on error, mirrors Added/Modified/Deleted events
// into store, and invokes onUpsert / onDelete so the caller triggers the right
// reload. PT is the pointer type of T (e.g. *networking.Ingress); the
// metav1.Object constraint gives access to the object's namespace and name.
// onDelete receives the deleted object so a caller can reload incrementally
// (e.g. drop just that one host) instead of rebuilding from the whole store.
//
// On every watch re-establishment it relists via listFn and reconciles store
// (resyncStore), then runs onResync — recovering any event dropped in the gap
// between one watch closing and the next opening (the bare Watch carries no
// resourceVersion and never replays history, so a missed Deleted would otherwise
// leave a stale entry — and stale route — forever).
func watchResource[T any, PT interface {
	*T
	metav1.Object
}](
	ctx context.Context,
	namespace, name string,
	watchFn func(ctx context.Context, namespace string) (watch.Interface, error),
	listFn func(ctx context.Context, namespace string) ([]T, error),
	store *sync.Map,
	onUpsert func(obj PT),
	onDelete func(obj PT),
	onResync func(),
) {
	for {
		w, err := watchFn(ctx, namespace)
		if err != nil {
			slog.Error("can not watch "+name, "error", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for event := range w.ResultChan() {
			obj, ok := event.Object.(PT)
			if !ok {
				continue
			}
			key := obj.GetNamespace() + "/" + obj.GetName()

			switch event.Type {
			case watch.Added, watch.Modified:
				store.Store(key, obj)
				onUpsert(obj)
			case watch.Deleted:
				store.Delete(key)
				onDelete(obj)
			default:
				continue
			}
		}

		w.Stop()
		slog.Info("restart " + name + " watcher")

		// The watch just ended; reconcile against the authoritative list before
		// reconnecting so anything dropped in the gap (e.g. a 410 Gone / watch-cache
		// compaction) self-heals instead of lingering forever.
		resyncStore[T, PT](ctx, namespace, name, listFn, store, onResync)
	}
}

// resyncStore relists the authoritative set via listFn and reconciles store to
// it: every listed object is stored, and any store key absent from the list is
// deleted (a missed Deleted). It then runs onResync to rebuild routing from the
// reconciled store. This needs no extra locking: each store is written only by
// its single watch goroutine, and resyncStore runs in that goroutine while the
// watch is stopped.
func resyncStore[T any, PT interface {
	*T
	metav1.Object
}](
	ctx context.Context,
	namespace, name string,
	listFn func(ctx context.Context, namespace string) ([]T, error),
	store *sync.Map,
	onResync func(),
) {
	if listFn == nil {
		return
	}
	items, err := listFn(ctx, namespace)
	if err != nil {
		slog.Error("can not relist "+name+" for resync", "error", err)
		return
	}

	present := make(map[string]struct{}, len(items))
	for i := range items {
		obj := PT(&items[i])
		key := obj.GetNamespace() + "/" + obj.GetName()
		present[key] = struct{}{}
		store.Store(key, obj)
	}

	var removed int
	store.Range(func(k, _ any) bool {
		key := k.(string)
		if _, ok := present[key]; !ok {
			store.Delete(key)
			removed++
		}
		return true
	})

	slog.Info("resync "+name, "listed", len(items), "removed_stale", removed)
	if onResync != nil {
		onResync()
	}
}

func (ctrl *Controller) watchIngresses(ctx context.Context) {
	watchResource(ctx, ctrl.watchNamespace, "ingresses", k8s.WatchIngresses, k8s.GetIngresses,
		&ctrl.watchedIngresses,
		func(_ *networking.Ingress) { ctrl.reloadIngress() },
		func(_ *networking.Ingress) { ctrl.reloadIngress() },
		ctrl.reloadIngress,
	)
}

func (ctrl *Controller) watchServices(ctx context.Context) {
	// a service change can change both port routing and which ingress backends
	// resolve, so refresh both tables.
	reload := func() {
		ctrl.reloadService()
		ctrl.reloadIngress()
	}
	watchResource(ctx, ctrl.watchNamespace, "services", k8s.WatchServices, k8s.GetServices,
		&ctrl.watchedServices,
		func(_ *v1.Service) { reload() },
		func(_ *v1.Service) { reload() },
		reload,
	)
}

func (ctrl *Controller) watchSecrets(ctx context.Context) {
	watchResource(ctx, ctrl.watchNamespace, "secrets", k8s.WatchSecrets, k8s.GetSecrets,
		&ctrl.watchedSecrets,
		func(_ *v1.Secret) { ctrl.reloadSecret() },
		func(_ *v1.Secret) { ctrl.reloadSecret() },
		ctrl.reloadSecret,
	)
}

func (ctrl *Controller) watchEndpointSlices(ctx context.Context) {
	// A single EndpointSlice event only touches its own Service's host, so both
	// upsert and delete recompute just that one host in place (by re-aggregating
	// the Service's slices from the store) instead of rebuilding the whole
	// endpoint table. The full rebuild (reloadEndpointDebounced) is reserved for
	// the initial sync / resync in firstReload, where the entire set is (re)listed.
	watchResource(ctx, ctrl.watchNamespace, "endpointslices", k8s.WatchEndpointSlices, k8s.GetEndpointSlices,
		&ctrl.watchedEndpointSlices,
		func(es *discovery.EndpointSlice) {
			ctrl.reloadEndpointSlice(es)
			// EndpointSlices carry the numeric port a *named* Service targetPort
			// resolves to, so a service whose named port wasn't resolvable at
			// service-reload time (slices not yet present) converges once its slices
			// arrive. Debounced, so high endpoint churn coalesces into at most one
			// cheap port-table rebuild per window.
			ctrl.reloadService()
		},
		// delete: the store has already dropped this slice, so re-aggregating the
		// Service drops the host when its last slice is gone.
		ctrl.reloadEndpointSlice,
		// resync: rebuild the full host-route table from the reconciled store.
		ctrl.reloadEndpointDebounced,
	)
}

func (ctrl *Controller) watchEndpoints(ctx context.Context) {
	// Legacy Endpoints watch — the fallback for a Service that has NO
	// EndpointSlice (e.g. hand-managed Endpoints labeled
	// endpointslice.kubernetes.io/skip-mirror=true, or a cluster without the
	// EndpointSlice mirroring controller). aggregateServiceIPs / resolveTargetPort
	// only consult this store when the Service has zero slices, so on any normal
	// Service these events recompute a host route that immediately re-prefers the
	// slices and changes nothing. Keyed by Service name (an Endpoints object is
	// named after its Service), matching buildHost.
	watchResource(ctx, ctrl.watchNamespace, "endpoints", k8s.WatchEndpoints, k8s.GetEndpoints,
		&ctrl.watchedEndpoints,
		func(ep *v1.Endpoints) {
			ctrl.reloadEndpointsObject(ep)
			ctrl.reloadService() // converge a named targetPort resolvable only from Endpoints
		},
		// delete: the store has already dropped this object, so re-aggregating the
		// Service drops the host when it has neither a slice nor an Endpoints object.
		ctrl.reloadEndpointsObject,
		// resync: rebuild the full host-route table from the reconciled stores.
		ctrl.reloadEndpointDebounced,
	)
}

func (ctrl *Controller) reloadIngress() {
	ctrl.reloadIngressDebounce.Call()
}

func (ctrl *Controller) reloadIngressDebounced() {
	defer func() {
		if err := recover(); err != nil {
			slog.Error("reload ingresses failed", "error", err)
			metric.Reload(false)
			return
		}
		metric.Reload(true)
	}()

	routes := make(map[string]http.Handler, routeSizeHint)
	var loaded, skipped int

	ctrl.watchedIngresses.Range(func(_, value any) bool {
		ing := value.(*networking.Ingress)

		if getIngressClass(ing) != IngressClass {
			slog.Debug("skip ingress", "namespace", ing.Namespace, "name", ing.Name)
			skipped++
			return true
		}

		slog.Debug("load ingress", "namespace", ing.Namespace, "name", ing.Name)
		loaded++

		var h parapet.Middlewares
		for _, m := range ctrl.plugins {
			m(plugin.Context{
				Middlewares: &h,
				Routes:      routes,
				Ingress:     ing,
			})
		}
		h.Use(parapet.MiddlewareFunc(retryMiddleware))

		if ing.Spec.DefaultBackend != nil {
			slog.Warn("ingress spec.defaultBackend not support", "namespace", ing.Namespace, "name", ing.Name)
		}

		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}

			for _, httpPath := range rule.HTTP.Paths {
				backend := httpPath.Backend
				if backend.Service == nil {
					slog.Warn("ingress backend service empty", "namespace", ing.Namespace, "name", ing.Name)
					continue
				}

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

				svcKey := ing.Namespace + "/" + backend.Service.Name

				v, ok := ctrl.watchedServices.Load(svcKey)
				if !ok {
					slog.Error("service not found", "namespace", ing.Namespace, "name", backend.Service.Name)
					continue
				}
				svc := v.(*v1.Service)

				// find port
				config, ok := getBackendConfig(&backend, svc)
				if !ok {
					slog.Error("port not found", "namespace", ing.Namespace, "name", backend.Service.Name, "port", backend.Service.Port.Name)
					continue
				}
				if config.PortNumber <= 0 { // missing port
					continue
				}

				target := buildHostPort(ing.Namespace, backend.Service.Name, config.PortNumber)
				handler := ctrl.makeHandler(ing, svc, config, target)
				host := strings.ToLower(rule.Host)
				switch pathType {
				case networking.PathTypePrefix:
					// register path as prefix
					src := host + strings.TrimSuffix(path, "/")
					if path != "/" {
						routes[src] = h.ServeHandler(handler)
					}
					src += "/"
					routes[src] = h.ServeHandler(handler)
					slog.Debug("registered path", "type", "prefix", "path", src, "target", target)
				case networking.PathTypeExact:
					src := host + strings.TrimSuffix(path, "/")
					if path == "/" {
						slog.Warn("register path type exact at root path is not supported, switch to prefix", "path", src, "target", target)
						src = host + path
					}
					routes[src] = h.ServeHandler(handler)
					slog.Debug("registered path", "type", "exact", "path", src, "target", target)
				case networking.PathTypeImplementationSpecific:
					src := host + path
					routes[src] = h.ServeHandler(handler)
					slog.Debug("registered path", "type", "specific", "path", src, "target", target)
				}
			}
		}

		return true
	})

	mux := buildRoutes(routes)
	knownHosts := buildKnownHosts(routes)
	ctrl.routes.Store(&routeState{mux: mux, knownHosts: knownHosts})
	slog.Info("reloaded ingresses", "loaded", loaded, "skipped", skipped, "routes", len(routes))
	ctrl.reloadSecret()
}

// currentMux returns the live routing mux. Internal/test accessor for the
// atomically-swapped route state.
func (ctrl *Controller) currentMux() *http.ServeMux {
	return ctrl.routes.Load().mux
}

// buildKnownHosts extracts the distinct host part (everything before the first
// '/') of each registered route key. Host-less routes (keys starting with '/')
// contribute nothing.
func buildKnownHosts(routes map[string]http.Handler) map[string]struct{} {
	hosts := make(map[string]struct{}, len(routes))
	for r := range routes {
		if i := strings.IndexByte(r, '/'); i > 0 {
			hosts[r[:i]] = struct{}{}
		}
	}
	return hosts
}

// IsKnownHost reports whether the current routes serve host (already lowercased
// and port-stripped by the upstream middleware, matching the registered keys).
func (ctrl *Controller) IsKnownHost(host string) bool {
	_, ok := ctrl.routes.Load().knownHosts[host]
	return ok
}

func (ctrl *Controller) reloadService() {
	ctrl.reloadServiceDebounce.Call()
}

func (ctrl *Controller) reloadServiceDebounced() {
	defer func() {
		if err := recover(); err != nil {
			slog.Error("reload services failed", "error", err)
		}
	}()

	addrToPort := make(map[string]string, endpointSizeHint)
	externalNames := make(map[string]string)

	ctrl.watchedServices.Range(func(_, value any) bool {
		s := value.(*v1.Service)

		// ExternalName services have no selector and thus no Endpoints object, so
		// they never get a pod-IP host route. Map the service host to its external
		// DNS name (dialed directly, resolved by the dialer) and map each declared
		// service port to itself — the external host is contacted on the port the
		// ingress references (targetPort is a pod concept and does not apply to a
		// DNS CNAME).
		if s.Spec.Type == v1.ServiceTypeExternalName {
			extName := strings.TrimSuffix(strings.TrimSpace(s.Spec.ExternalName), ".")
			if extName == "" {
				slog.Error("externalName service has empty spec.externalName", "namespace", s.Namespace, "name", s.Name)
				return true
			}
			externalNames[buildHost(s.Namespace, s.Name)] = extName
			for _, p := range s.Spec.Ports {
				addr := buildHostPort(s.Namespace, s.Name, int(p.Port))
				addrToPort[addr] = strconv.Itoa(int(p.Port))
			}
			return true
		}

		// build route target port
		for _, p := range s.Spec.Ports {
			target, ok := ctrl.resolveTargetPort(s, p)
			if !ok {
				// named targetPort not resolvable yet (no endpoints / no matching
				// subset port); skip rather than route to ":0". It converges when the
				// service's endpoints arrive (watchEndpoints triggers reloadService).
				continue
			}
			addr := buildHostPort(s.Namespace, s.Name, int(p.Port))
			addrToPort[addr] = target
		}

		return true
	})

	ctrl.routeTable.SetPortRoutes(addrToPort)
	ctrl.routeTable.SetExternalNameRoutes(externalNames)
	slog.Info("reloaded services", "ports", len(addrToPort), "externalNames", len(externalNames))
}

// resolveTargetPort returns the concrete numeric pod port (as a string) a
// ServicePort routes to. A numeric targetPort is used directly. A *named*
// targetPort (intstr.String) carries no number in the Service object, so it is
// resolved from the service's EndpointSlices — matching the EndpointPort whose
// Name equals this ServicePort's Name (Kubernetes keys EndpointPort.Name to
// ServicePort.Name). A Service with no EndpointSlice falls back to its legacy
// Endpoints object (the same authoritative-slice rule as aggregateServiceIPs).
// Returns ok=false when a named port can't be resolved yet, so the caller skips
// it instead of producing a dead ":0" route.
func (ctrl *Controller) resolveTargetPort(s *v1.Service, p v1.ServicePort) (string, bool) {
	if p.TargetPort.Type == intstr.Int {
		if p.TargetPort.IntVal > 0 {
			return strconv.Itoa(int(p.TargetPort.IntVal)), true
		}
		// An unset targetPort is normally defaulted to the service port by the
		// apiserver; fall back to that identity mapping defensively.
		return strconv.Itoa(int(p.Port)), true
	}

	// Scan the service's EndpointSlices (a service may own several) for the
	// matching named port. All slices of a service share the same port set, so
	// the first match wins.
	var resolved string
	var found, sliceExists bool
	ctrl.watchedEndpointSlices.Range(func(_, value any) bool {
		es := value.(*discovery.EndpointSlice)
		if es.Namespace != s.Namespace || sliceServiceName(es) != s.Name {
			return true
		}
		sliceExists = true
		for _, epp := range es.Ports {
			if epp.Name != nil && *epp.Name == p.Name && epp.Port != nil && *epp.Port > 0 {
				resolved = strconv.Itoa(int(*epp.Port))
				found = true
				return false
			}
		}
		return true
	})
	if found {
		return resolved, true
	}
	if sliceExists {
		// Slices are authoritative; do not fall back when they exist but lack the port.
		return "", false
	}

	// No EndpointSlice for this Service — fall back to the legacy Endpoints object.
	if v, ok := ctrl.watchedEndpoints.Load(s.Namespace + "/" + s.Name); ok {
		ep := v.(*v1.Endpoints)
		for _, ss := range ep.Subsets {
			for _, epp := range ss.Ports {
				if epp.Name == p.Name && epp.Port > 0 {
					return strconv.Itoa(int(epp.Port)), true
				}
			}
		}
	}
	return "", false
}

func (ctrl *Controller) reloadSecret() {
	ctrl.reloadSecretDebounce.Call()
}

func (ctrl *Controller) reloadSecretDebounced() {
	defer func() {
		if err := recover(); err != nil {
			slog.Error("reload secrets failed", "error", err)
		}
	}()

	var certs []*tls.Certificate

	if ctrl.LoadAllCerts {
		// Load every TLS-typed secret in the watch namespace. The cert table
		// indexes by SAN and does SNI lookup with wildcard climbing, so this
		// is enough for a wildcard cert in tls-example-com to serve SNI for
		// foo.example.com without any ingress wiring.
		ctrl.watchedSecrets.Range(func(_, value any) bool {
			s := value.(*v1.Secret)
			if s.Type != v1.SecretTypeTLS {
				return true
			}
			crt, err := tls.X509KeyPair(s.Data["tls.crt"], s.Data["tls.key"])
			if err != nil {
				slog.Error("can not load x509 certificate", "namespace", s.Namespace, "name", s.Name, "error", err)
				return true
			}
			certs = append(certs, &crt)
			return true
		})
		ctrl.certTable.Set(certs)
		slog.Info("reloaded secrets", "certs", len(certs))
		return
	}

	secretToBuild := make(map[string]struct{}, secretSizeHint)

	ctrl.watchedIngresses.Range(func(_, value any) bool {
		ing := value.(*networking.Ingress)
		for _, t := range ing.Spec.TLS {
			key := ing.Namespace + "/" + t.SecretName
			secretToBuild[key] = struct{}{}
		}
		return true
	})

	// build certs
	for key := range secretToBuild {
		v, ok := ctrl.watchedSecrets.Load(key)
		if !ok {
			slog.Error("secret not found", "key", key)
			continue
		}
		s := v.(*v1.Secret)
		crt, err := tls.X509KeyPair(s.Data["tls.crt"], s.Data["tls.key"])
		if err != nil {
			slog.Error("can not load x509 certificate", "namespace", s.Namespace, "name", s.Name, "error", err)
			continue
		}
		certs = append(certs, &crt)
	}

	ctrl.certTable.Set(certs)
	slog.Info("reloaded secrets", "certs", len(certs))
}

// reloadEndpointDebounced rebuilds the entire host -> pod-IP table from the
// whole watched-endpointslices store (with a legacy-Endpoints fallback). It is
// the initial-sync / resync path (called from firstReload); steady-state endpoint
// events are applied incrementally per host by reloadEndpointSlice /
// reloadEndpointsObject and never come here.
//
// A Service may own several EndpointSlices, so this groups slices by their
// owning Service (the kubernetes.io/service-name label) in a single pass and
// unions the ready addresses of all of a Service's slices into one RRLB. A
// Service that has NO slice falls back to its legacy Endpoints object — slices
// are authoritative, so a host already produced from slices is never overwritten.
func (ctrl *Controller) reloadEndpointDebounced() {
	defer func() {
		if err := recover(); err != nil {
			slog.Error("reload endpoints failed", "error", err)
		}
	}()

	// Serialize with the incremental per-host updates (both watch goroutines):
	// this full replace and a single-host SetHostRoute must not interleave.
	ctrl.endpointReloadMu.Lock()
	defer ctrl.endpointReloadMu.Unlock()

	routes := make(map[string]*route.RRLB, endpointSizeHint)
	sliceHosts := make(map[string]struct{}, endpointSizeHint)
	ctrl.watchedEndpointSlices.Range(func(_, value any) bool {
		es := value.(*discovery.EndpointSlice)
		svc := sliceServiceName(es)
		if svc == "" {
			return true
		}
		host := buildHost(es.Namespace, svc)
		sliceHosts[host] = struct{}{} // slice-managed (even if it yields no ready IP)
		lb := routes[host]
		if lb == nil {
			lb = &route.RRLB{}
			routes[host] = lb
		}
		appendReadyIPs(lb, es)
		return true
	})

	// Fallback: services with no EndpointSlice are routed from their legacy
	// Endpoints object. A host present in sliceHosts is skipped — slices win even
	// when they currently resolve to zero ready addresses.
	ctrl.watchedEndpoints.Range(func(_, value any) bool {
		ep := value.(*v1.Endpoints)
		host := buildHost(ep.Namespace, ep.Name)
		if _, ok := sliceHosts[host]; ok {
			return true
		}
		lb := routes[host]
		if lb == nil {
			lb = &route.RRLB{}
			routes[host] = lb
		}
		appendEndpointsReadyIPs(lb, ep)
		return true
	})

	// Drop services that yielded no ready address — an empty RRLB would 503
	// anyway, and leaving it out keeps Lookup's host-present check meaningful.
	for host, lb := range routes {
		if len(lb.IPs) == 0 {
			delete(routes, host)
		}
	}

	ctrl.routeTable.SetHostRoutes(routes)
	slog.Info("reloaded endpoints", "hosts", len(routes))
}

// reloadEndpointSlice recomputes the host route for the Service owning es by
// re-aggregating every slice the Service currently has in the store, then
// swapping just that one host entry. It serves both upsert and delete events:
// on delete the store has already dropped es, so an empty aggregate deletes the
// host (SetHostRoute(nil)). The store is written only by the single endpoint
// watch goroutine, which is also the only caller here, so the Range is consistent.
func (ctrl *Controller) reloadEndpointSlice(es *discovery.EndpointSlice) {
	svc := sliceServiceName(es)
	if svc == "" {
		slog.Warn("endpointslice without service-name label", "namespace", es.Namespace, "name", es.Name)
		return
	}
	slog.Debug("reload endpointslice", "namespace", es.Namespace, "service", svc, "name", es.Name)

	ctrl.endpointReloadMu.Lock()
	defer ctrl.endpointReloadMu.Unlock()
	ctrl.routeTable.SetHostRoute(buildHost(es.Namespace, svc), ctrl.aggregateServiceIPs(es.Namespace, svc))
}

// reloadEndpointsObject recomputes the host route for the Service named by a
// legacy Endpoints object (its name is the Service name). It re-runs the same
// slice-first aggregation, so the legacy addresses take effect only while the
// Service has no EndpointSlice; the moment slices appear they win. Serves both
// upsert and delete (delete leaves an empty aggregate that drops the host).
func (ctrl *Controller) reloadEndpointsObject(ep *v1.Endpoints) {
	slog.Debug("reload endpoints", "namespace", ep.Namespace, "name", ep.Name)

	ctrl.endpointReloadMu.Lock()
	defer ctrl.endpointReloadMu.Unlock()
	ctrl.routeTable.SetHostRoute(buildHost(ep.Namespace, ep.Name), ctrl.aggregateServiceIPs(ep.Namespace, ep.Name))
}

// aggregateServiceIPs unions the ready addresses of every watched EndpointSlice
// owned by namespace/serviceName into one RRLB. EndpointSlices are authoritative:
// if the Service owns at least one slice (even an empty one), its slices alone
// decide the route. Only when the Service has NO slice does it fall back to the
// legacy Endpoints object (keyed by Service name). Returns nil when neither
// source yields a ready address (so SetHostRoute deletes the host).
func (ctrl *Controller) aggregateServiceIPs(namespace, serviceName string) *route.RRLB {
	var b route.RRLB
	var sliceExists bool
	ctrl.watchedEndpointSlices.Range(func(_, value any) bool {
		es := value.(*discovery.EndpointSlice)
		if es.Namespace != namespace || sliceServiceName(es) != serviceName {
			return true
		}
		sliceExists = true
		appendReadyIPs(&b, es)
		return true
	})

	if !sliceExists {
		// No EndpointSlice for this Service — fall back to its legacy Endpoints.
		if v, ok := ctrl.watchedEndpoints.Load(namespace + "/" + serviceName); ok {
			appendEndpointsReadyIPs(&b, v.(*v1.Endpoints))
		}
	}

	if len(b.IPs) == 0 {
		return nil
	}
	return &b
}

func (ctrl *Controller) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return ctrl.certTable.Get(clientHello)
}

// Healthz returns health check middleware
func (ctrl *Controller) Healthz() parapet.Middleware {
	return ctrl.health
}

type backendConfig struct {
	Protocol   string
	PortName   string
	PortNumber int
}

func buildHost(namespace, name string) string {
	// service.namespace.svc.cluster.local
	return name + "." + namespace + ".svc.cluster.local"
}

func buildHostPort(namespace, name string, port int) string {
	// service.namespace.svc.cluster.local:port
	return name + "." + namespace + ".svc.cluster.local:" + strconv.Itoa(port)
}

func buildRoutes(routes map[string]http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	for r, h := range routes {
		func() {
			defer func() {
				err := recover()
				if err != nil {
					slog.Error("register handler failed", "path", r, "error", err)
				}
			}()
			mux.Handle(r, h)
		}()
	}
	return mux
}

func getIngressClass(ing *networking.Ingress) string {
	if ing.Spec.IngressClassName != nil {
		return *ing.Spec.IngressClassName
	}
	if ing.Annotations != nil {
		return ing.Annotations["kubernetes.io/ingress.class"]
	}
	return ""
}

func getBackendConfig(backend *networking.IngressBackend, svc *v1.Service) (config backendConfig, ok bool) {
	// specifies port by name
	if backend.Service.Port.Name != "" {
		config.PortName = backend.Service.Port.Name

		// find port number
		for _, p := range svc.Spec.Ports {
			if p.Name == backend.Service.Port.Name {
				config.PortNumber = int(p.Port)
				if p.AppProtocol != nil {
					config.Protocol = *p.AppProtocol
				}
			}
		}
		if config.PortNumber == 0 {
			return config, false
		}
		ok = true
		return
	}

	// specifies port by number
	config.PortNumber = int(backend.Service.Port.Number)

	// find the matching service port (for its name + appProtocol). A backend that
	// references a numeric port the service does not expose must be reported as
	// not-found (ok=false), mirroring the port-by-name branch — otherwise the
	// caller registers a route whose Lookup always misses, silently 503-ing every
	// request with no "port not found" log.
	for _, p := range svc.Spec.Ports {
		if p.Port == backend.Service.Port.Number {
			config.PortName = p.Name
			if p.AppProtocol != nil {
				config.Protocol = *p.AppProtocol
			}
			ok = true
		}
	}
	return
}

func (ctrl *Controller) makeHandler(ing *networking.Ingress, svc *v1.Service, config backendConfig, target string) http.Handler {
	// Precompute the per-Service auto-h2c cache key once at route-build time — it's
	// constant for this route. Only built when auto-h2c is enabled, so disabled
	// deployments pay nothing per request (no concat/alloc on the hot path).
	var upstreamKey string
	if ctrl.proxy.AutoH2CEnabled() {
		upstreamKey = svc.Namespace + "/" + svc.Name + ":" + strconv.Itoa(config.PortNumber)
	}
	// Immutable per-Service attribution for backend connection metrics. These are
	// constant for this route, so build them once. They mirror the
	// serviceType/serviceName/namespace state fields (still stamped below for the
	// access log and per-request metrics, both read in the request goroutine) but
	// are carried to the dialer in a context value that is never cleared or pooled.
	// The dialer can run on a background goroutine that outlives the request, after
	// the state map has been recycled, so it must not read the map — see
	// proxy.WithBackendAttr.
	serviceType := string(svc.Spec.Type)
	serviceName := svc.Name
	namespace := svc.Namespace
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := state.Get(r.Context())
		s["serviceType"] = serviceType
		s["serviceName"] = serviceName
		if upstreamKey != "" { // auto-h2c negative-cache key (proxy reads it)
			s["upstreamKey"] = upstreamKey
		}

		target := ctrl.routeTable.Lookup(target)
		if target == "" { // fail fast
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}

		if config.Protocol != "" {
			r.URL.Scheme = config.Protocol
		}
		r.RemoteAddr = "" // prevent httputil.ReverseProxy append remote addr to XFF
		r.URL.Host = target

		s["serviceTarget"] = target

		r = r.WithContext(proxy.WithBackendAttr(r.Context(), serviceType, namespace, serviceName))

		ctrl.proxy.ServeHTTP(w, r)
	})
}

// sliceServiceName returns the name of the Service an EndpointSlice belongs to,
// from the well-known kubernetes.io/service-name label, or "" if unset (e.g. a
// hand-written slice not owned by a Service — skipped, as it maps to no host).
func sliceServiceName(es *discovery.EndpointSlice) string {
	return es.Labels[discovery.LabelServiceName]
}

// appendReadyIPs appends the ready addresses of an EndpointSlice to lb. Only
// IPv4/IPv6 slices contribute pod IPs; FQDN slices carry hostnames the RRLB
// can't treat as pod IPs (and never arise for the normal selector-backed
// services this resolves). A nil Ready is treated as ready per the EndpointSlice
// contract, matching the legacy Endpoints.Subsets[].Addresses behavior (which
// only listed ready addresses).
func appendReadyIPs(lb *route.RRLB, es *discovery.EndpointSlice) {
	if es.AddressType == discovery.AddressTypeFQDN {
		return
	}
	for _, e := range es.Endpoints {
		if e.Conditions.Ready != nil && !*e.Conditions.Ready {
			continue
		}
		lb.IPs = append(lb.IPs, e.Addresses...)
	}
}

// appendEndpointsReadyIPs appends the ready addresses of a legacy Endpoints
// object to lb. Subsets[].Addresses holds the ready set (NotReadyAddresses is
// excluded), mirroring appendReadyIPs for the no-EndpointSlice fallback.
func appendEndpointsReadyIPs(lb *route.RRLB, ep *v1.Endpoints) {
	for _, ss := range ep.Subsets {
		for _, addr := range ss.Addresses {
			lb.IPs = append(lb.IPs, addr.IP)
		}
	}
}
