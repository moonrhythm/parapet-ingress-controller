//! Prometheus metrics, registered in the process-default registry so Pingora's
//! `prometheus_http_service` (on :9187) serves them. Metric names and labels
//! match the Go controller exactly so existing dashboards keep working.
//!
//! Known gap (Phase 5): the per-addr backend connection/byte counters
//! (`parapet_backend_*`) and downstream `parapet_connections`/`network_*` are
//! not yet wired — Pingora pools upstream connections, so those need a custom
//! IO accounting layer.

use std::sync::OnceLock;

use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge_vec, HistogramVec,
    IntCounterVec, IntGaugeVec,
};

struct Metrics {
    requests: IntCounterVec,
    duration: HistogramVec,
    reload: IntCounterVec,
    host_active: IntGaugeVec,
    host_ratelimit: IntCounterVec,
    backend_read: IntCounterVec,
    backend_write: IntCounterVec,
}

fn metrics() -> &'static Metrics {
    static M: OnceLock<Metrics> = OnceLock::new();
    M.get_or_init(|| Metrics {
        requests: register_int_counter_vec!(
            "parapet_requests",
            "Total requests",
            &[
                "host",
                "status",
                "method",
                "ingress_name",
                "ingress_namespace",
                "service_type",
                "service_name"
            ]
        )
        .expect("register parapet_requests"),
        duration: register_histogram_vec!(
            "parapet_service_duration_seconds",
            "Service response duration in seconds",
            &["service_type", "service_namespace", "service_name"]
        )
        .expect("register parapet_service_duration_seconds"),
        reload: register_int_counter_vec!("parapet_reload", "Reloads", &["success"])
            .expect("register parapet_reload"),
        host_active: register_int_gauge_vec!(
            "parapet_host_active_requests",
            "In-flight requests per host",
            &["host", "upgrade"]
        )
        .expect("register parapet_host_active_requests"),
        host_ratelimit: register_int_counter_vec!(
            "parapet_host_ratelimit_requests",
            "Requests rejected by host concurrency limit",
            &["host"]
        )
        .expect("register parapet_host_ratelimit_requests"),
        // Bytes read from / written to a backend, keyed by pod addr (matches the
        // Go controller's net.Conn wrapper). NOTE: counts response/request *body*
        // bytes (the granularity Pingora's body filters expose); unlike Go's
        // conn-level wrapper this excludes request/response header bytes.
        backend_read: register_int_counter_vec!(
            "parapet_backend_network_read_bytes",
            "Bytes read from backend",
            &["addr"]
        )
        .expect("register parapet_backend_network_read_bytes"),
        backend_write: register_int_counter_vec!(
            "parapet_backend_network_write_bytes",
            "Bytes written to backend",
            &["addr"]
        )
        .expect("register parapet_backend_network_write_bytes"),
    })
}

pub fn backend_read_add(addr: &str, n: u64) {
    metrics().backend_read.with_label_values(&[addr]).inc_by(n);
}

pub fn backend_write_add(addr: &str, n: u64) {
    metrics().backend_write.with_label_values(&[addr]).inc_by(n);
}

pub fn host_active_inc(host: &str, upgrade: &str) {
    metrics()
        .host_active
        .with_label_values(&[host, upgrade])
        .inc();
}

pub fn host_active_dec(host: &str, upgrade: &str) {
    metrics()
        .host_active
        .with_label_values(&[host, upgrade])
        .dec();
}

pub fn host_ratelimit_inc(host: &str) {
    metrics().host_ratelimit.with_label_values(&[host]).inc();
}

/// Per-request labels captured for metric emission.
pub struct RequestMetric<'a> {
    pub host: &'a str,
    pub status: u16,
    pub method: &'a str,
    pub ingress_name: &'a str,
    pub ingress_namespace: &'a str,
    pub service_type: &'a str,
    pub service_name: &'a str,
    pub duration_secs: f64,
}

pub fn record_request(m: &RequestMetric) {
    let metrics = metrics();
    let status = m.status.to_string();
    metrics
        .requests
        .with_label_values(&[
            m.host,
            &status,
            m.method,
            m.ingress_name,
            m.ingress_namespace,
            m.service_type,
            m.service_name,
        ])
        .inc();
    // service_namespace == ingress_namespace in the Go controller's state
    metrics
        .duration
        .with_label_values(&[m.service_type, m.ingress_namespace, m.service_name])
        .observe(m.duration_secs);
}

pub fn inc_reload(success: bool) {
    metrics()
        .reload
        .with_label_values(&[if success { "1" } else { "0" }])
        .inc();
}
