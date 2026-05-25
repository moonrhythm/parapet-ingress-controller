//! Shared, hot-swappable runtime state. The router and cert table live behind
//! `ArcSwap` (lock-free reads, atomic replace on reload); the route table keeps
//! its own internal locking. [`Shared::rebuild`] is the single reload entry
//! point — it runs the reconcile functions over a [`Snapshot`] and swaps the
//! results in, mirroring the Go controller's `mux` swap under `RWMutex`.

use std::collections::HashMap;
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
        self.router.store(Arc::new(router));
        self.route_table
            .set_port_routes(build_port_routes(&services));
        self.route_table
            .set_host_routes(build_host_routes(&endpoints));
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
