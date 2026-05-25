//! parapet-ingress-controller binary. Wires the live data source (fs or
//! cluster watch) to the Pingora proxy server. Built only with both the
//! `proxy` and `cluster` features (see Cargo.toml `required-features`).

use std::path::Path;
use std::sync::Arc;

use controller::k8s;
use controller::proxy::limit::HostConcurrency;
use controller::proxy::server::{run, ServeConfig};
use controller::proxy::{Limits, TrustProxy};
use controller::shared::Shared;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn env_usize(key: &str) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Parse a Go-style duration like "30s", "0s", "500ms", "1m", "1h", or a bare
/// integer (seconds). Single-unit only.
fn parse_duration(s: &str) -> Option<std::time::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, mult_ms) = if let Some(v) = s.strip_suffix("ms") {
        (v, 1u64)
    } else if let Some(v) = s.strip_suffix('s') {
        (v, 1_000)
    } else if let Some(v) = s.strip_suffix('m') {
        (v, 60_000)
    } else if let Some(v) = s.strip_suffix('h') {
        (v, 3_600_000)
    } else {
        (s, 1_000) // bare = seconds
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .map(|n| std::time::Duration::from_millis(n * mult_ms))
}

fn build_limits() -> Limits {
    let country_headers: Vec<String> = env_or("HOST_COUNTRY_HEADER", "")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let country_cap = env_usize("HOST_COUNTRY_CONCURRENT_CAPACITY");
    Limits {
        host: HostConcurrency::new(
            env_usize("HOST_CONCURRENT_CAPACITY"),
            env_usize("HOST_CONCURRENT_SIZE"),
        ),
        country: if country_headers.is_empty() {
            None
        } else {
            HostConcurrency::new(country_cap, env_usize("HOST_COUNTRY_CONCURRENT_SIZE"))
        },
        country_headers,
    }
}

fn main() {
    // surface pingora's internal logging (h2 handshake errors, etc.); RUST_LOG overrides.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // kube's rustls client (and reqwest) need a process-default crypto provider.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Pingora's prometheus endpoint serves the default registry but, unlike Go's
    // client_golang, registers no process collector. Start our own (reads /proc,
    // Linux-only) so the pod exposes process_cpu_seconds_total (float, ms
    // precision) / resident+virtual memory / fds / network bytes like Go.
    #[cfg(target_os = "linux")]
    controller::proxy::procmetrics::start();

    let ingress_class = env_or("INGRESS_CLASS", "parapet");
    let load_all_certs = std::env::var("LOAD_ALL_CERTS").ok().as_deref() == Some("true");
    let http_port = env_or("HTTP_PORT", "80");
    // HTTPS_PORT: unset -> default 443; explicitly empty -> disable HTTPS (HTTP-only,
    // e.g. the internal-ingress controller). env_or can't distinguish unset from a
    // set-but-empty value, so match directly; an empty value yields no https_addr.
    let https_port = match std::env::var("HTTPS_PORT") {
        Ok(s) => s,
        Err(_) => "443".to_string(),
    };
    let watch_namespace = std::env::var("WATCH_NAMESPACE")
        .ok()
        .filter(|s| !s.is_empty());
    let backend = env_or("KUBERNETES_BACKEND", "cluster");
    let trust = Arc::new(TrustProxy::parse(&env_or("TRUST_PROXY", "")));
    let limits = Arc::new(build_limits());
    let log_enabled = std::env::var("DISABLE_LOG").ok().as_deref() != Some("true");
    let debug = std::env::var("DEBUG_ENDPOINTS").ok().as_deref() == Some("true");
    let wait_before_shutdown = std::env::var("WAIT_BEFORE_SHUTDOWN")
        .ok()
        .and_then(|s| parse_duration(&s))
        .unwrap_or_else(|| std::time::Duration::from_secs(30));
    // Maps to Pingora's process-global upstream keepalive pool (see ServeConfig).
    let upstream_keepalive_pool_size = std::env::var("TR_MAX_IDLE_CONNS_PER_HOST")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0);
    // POD_NAMESPACE is informational (parity with the Go controller's startup log).
    let pod_namespace = env_or("POD_NAMESPACE", "");
    eprintln!(
        "[config] ingress_class={ingress_class} watch_namespace={} pod_namespace={pod_namespace} \
         load_all_certs={load_all_certs} http_port={http_port} https_port={https_port} \
         log={log_enabled} backend={backend}",
        watch_namespace.as_deref().unwrap_or("(all)")
    );

    let shared = Shared::new(ingress_class, load_all_certs);

    match backend.as_str() {
        // static manifests; one-shot load, no watch (local dev / smoke tests)
        "fs" => {
            let dir = std::env::var("KUBERNETES_FS")
                .expect("KUBERNETES_FS is required for the fs backend");
            let snap = k8s::fs::load_dir(Path::new(&dir)).expect("load fs manifests");
            eprintln!(
                "fs backend: {} ingresses, {} services, {} endpoints, {} secrets",
                snap.ingresses.len(),
                snap.services.len(),
                snap.endpoints.len(),
                snap.secrets.len()
            );
            shared.rebuild(&snap);
        }
        // live cluster watch on a dedicated runtime thread
        _ => {
            let shared = shared.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("build tokio runtime");
                rt.block_on(async move {
                    if let Err(e) = k8s::cluster::run(shared, watch_namespace).await {
                        eprintln!("k8s watch error: {e}");
                    }
                });
            });
        }
    }

    let https_addr = if https_port.is_empty() {
        None
    } else {
        Some(format!("0.0.0.0:{https_port}"))
    };
    run(
        shared,
        ServeConfig {
            http_addr: format!("0.0.0.0:{http_port}"),
            https_addr,
            metrics_addr: "0.0.0.0:9187".to_string(),
            trust,
            limits,
            log_enabled,
            debug,
            wait_before_shutdown,
            upstream_keepalive_pool_size,
        },
    );
}
