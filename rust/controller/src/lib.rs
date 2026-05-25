//! parapet-ingress-controller (Rust port).
//!
//! Phase 1 builds the pure routing/reconcile core, decoupled from the HTTP
//! server (pingora) and the Kubernetes client (kube-rs), so it can be unit
//! tested exhaustively against the Go implementation's behavior.

pub mod cert;
pub mod config;
pub mod k8s;
pub mod reconcile;
pub mod route;
pub mod router;
pub mod shared;

#[cfg(feature = "proxy")]
pub mod proxy;
