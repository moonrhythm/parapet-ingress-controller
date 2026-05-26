//! Shared, hot-swappable runtime state. The router and cert table live behind
//! `ArcSwap` (lock-free reads, atomic replace on reload); the route table keeps
//! its own internal locking. [`Shared::rebuild`] is the single reload entry
//! point — it runs the reconcile functions over a [`Snapshot`] and swaps the
//! results in, mirroring the Go controller's `mux` swap under `RWMutex`.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use crate::cert::{LoadedCert, Table as CertTable};
use crate::k8s::Snapshot;
use crate::reconcile::{
    build_certs, build_host_routes, build_port_routes, build_router, RouteEntry,
};
use crate::route::Table as RouteTable;
use crate::router::Router;

pub struct Shared {
    pub router: ArcSwap<Router<RouteEntry>>,
    pub route_table: Arc<RouteTable>,
    pub certs: ArcSwap<CertTable<LoadedCert>>,
    /// Distinct hosts the router serves, for bounding host-labeled metric
    /// cardinality (an unknown Host is collapsed to a sentinel label).
    known_hosts: ArcSwap<HashSet<String>>,
    ready: AtomicBool,
    ingress_class: String,
    load_all_certs: bool,
}

impl Shared {
    pub fn new(ingress_class: impl Into<String>, load_all_certs: bool) -> Arc<Self> {
        Arc::new(Self {
            router: ArcSwap::from_pointee(Router::new(HashMap::new())),
            route_table: Arc::new(RouteTable::new()),
            certs: ArcSwap::from_pointee(CertTable::empty()),
            known_hosts: ArcSwap::from_pointee(HashSet::new()),
            ready: AtomicBool::new(false),
            ingress_class: ingress_class.into(),
            load_all_certs,
        })
    }

    /// True once the first reload has completed (drives readiness probes).
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    /// Flip to not-ready on shutdown so k8s/load balancers deregister this pod.
    pub fn set_not_ready(&self) {
        self.ready.store(false, Ordering::Relaxed);
    }

    /// Whether the router serves any route for `host` (already lowercased by the
    /// caller). Used to bound host-labeled metric cardinality.
    pub fn is_known_host(&self, host: &str) -> bool {
        self.known_hosts.load().contains(host)
    }

    /// Rebuild every table from `snap` and atomically swap them in.
    pub fn rebuild(&self, snap: &Snapshot) {
        let ingresses: Vec<&_> = snap.ingresses.iter().map(|a| a.as_ref()).collect();
        let services: Vec<&_> = snap.services.iter().map(|a| a.as_ref()).collect();
        let endpoints: Vec<&_> = snap.endpoints.iter().map(|a| a.as_ref()).collect();
        let secrets: Vec<&_> = snap.secrets.iter().map(|a| a.as_ref()).collect();

        let svc_map: HashMap<String, &_> = services
            .iter()
            .map(|s| (obj_key(&s.metadata), *s))
            .collect();
        let sec_map: HashMap<String, &_> =
            secrets.iter().map(|s| (obj_key(&s.metadata), *s)).collect();

        let router = build_router(&ingresses, &svc_map, &self.ingress_class);
        let n_routes = router.len();
        let patterns = router.patterns();
        // Distinct hosts the router serves (the substring before the first '/' of
        // each `host+path` pattern; host-less patterns contribute nothing). Drives
        // metric-label sanitization so unknown Hosts can't blow up cardinality.
        let known_hosts: HashSet<String> = patterns
            .iter()
            .filter_map(|p| {
                let host = p.split('/').next().unwrap_or("");
                (!host.is_empty()).then(|| host.to_ascii_lowercase())
            })
            .collect();
        // Bound the per-pattern rate-limit map to the live route set, so windows
        // for deleted routes don't linger for the process lifetime.
        #[cfg(feature = "proxy")]
        crate::proxy::ratelimit::windows().retain_patterns(&patterns.iter().copied().collect());
        self.known_hosts.store(Arc::new(known_hosts));
        self.router.store(Arc::new(router));
        self.route_table
            .set_port_routes(build_port_routes(&services));

        let host_routes = build_host_routes(&endpoints);
        // Drop addr-keyed backend metric series for pod IPs that are no longer
        // routable; otherwise the registry accumulates a dead series per pod IP
        // ever seen, since IPs churn on every deploy.
        #[cfg(feature = "proxy")]
        crate::proxy::metrics::prune_backend_addrs(
            &host_routes
                .values()
                .flat_map(|lb| lb.ips())
                .map(String::as_str)
                .collect(),
        );
        self.route_table.set_host_routes(host_routes);
        // Prune stale bad-addr marks. The route maps above are replaced wholesale,
        // but the bad-addr set persists for the process lifetime, so without this
        // it grows one entry per distinct failed pod IP forever (pod IPs churn on
        // every deploy — exactly when reloads fire).
        self.route_table.prune_bad();
        let certs = build_certs(&ingresses, &sec_map, self.load_all_certs);
        let n_certs = certs.len();
        self.certs.store(Arc::new(CertTable::build(certs)));

        // Operational reload log (always on, like the Go controller's slog). Lets
        // an operator see whether the watch delivered objects and what reconcile
        // produced: ingresses=0 -> watch empty; ingresses>0 routes=0 -> class
        // mismatch; certs=0 with a TLS ingress -> secret not referenced / unparsed.
        eprintln!(
            "[reload] in: ingresses={} services={} endpoints={} secrets={} | out: routes={} certs={} | class={:?} load_all_certs={}",
            ingresses.len(),
            services.len(),
            endpoints.len(),
            secrets.len(),
            n_routes,
            n_certs,
            self.ingress_class,
            self.load_all_certs,
        );

        self.ready.store(true, Ordering::Relaxed);

        #[cfg(feature = "proxy")]
        crate::proxy::metrics::inc_reload(true);
    }
}

fn obj_key(meta: &ObjectMeta) -> String {
    format!(
        "{}/{}",
        meta.namespace.as_deref().unwrap_or(""),
        meta.name.as_deref().unwrap_or("")
    )
}
