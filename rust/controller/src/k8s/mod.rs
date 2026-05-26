//! Kubernetes data sources. A [`Snapshot`] is the current set of watched
//! objects; it feeds [`crate::shared::Shared::rebuild`]. Two producers:
//! the live `cluster` watcher (kube-rs, behind the `cluster` feature) and the
//! `fs` backend (static YAML, for local dev / tests; mirrors `k8s/fs.go`).

use std::sync::Arc;

use k8s_openapi::api::core::v1::{ConfigMap, Endpoints, Secret, Service};
use k8s_openapi::api::networking::v1::Ingress;

#[derive(Default)]
pub struct Snapshot {
    pub ingresses: Vec<Arc<Ingress>>,
    pub services: Vec<Arc<Service>>,
    pub endpoints: Vec<Arc<Endpoints>>,
    pub secrets: Vec<Arc<Secret>>,
    /// WAF ConfigMaps (label `parapet.moonrhythm.io/waf`). Populated by the fs
    /// backend; the live cluster watch feeds the WAF through its own reflector
    /// (decoupled from `rebuild`), so this stays empty there.
    pub configmaps: Vec<Arc<ConfigMap>>,
}

pub mod fs;

#[cfg(feature = "cluster")]
pub mod cluster;
