//! Prometheus metrics, registered in the process-default registry so Pingora's
//! `prometheus_http_service` (on :9187) serves them. Metric names and labels
//! match the Go controller exactly so existing dashboards keep working.
//!
//! Backend/downstream byte counters (`parapet_backend_network_*`,
//! `parapet_network_*`) and `parapet_backend_connections` are wired (the last as
//! an in-flight-per-addr approximation, since Pingora pools upstream
//! connections). `parapet_connections` (downstream gauge by connection state)
//! has no Pingora `ConnState` equivalent and is not implemented.

use std::sync::OnceLock;

use prometheus::{
    register_histogram_vec, register_int_counter, register_int_counter_vec, register_int_gauge_vec,
    HistogramVec, IntCounter, IntCounterVec, IntGaugeVec,
};

struct Metrics {
    requests: IntCounterVec,
    duration: HistogramVec,
    reload: IntCounterVec,
    host_active: IntGaugeVec,
    host_ratelimit: IntCounterVec,
    backend_read: IntCounterVec,
    backend_write: IntCounterVec,
    backend_conn: IntGaugeVec,
    net_request: IntCounter,
    net_response: IntCounter,
    tls_no_cert: IntCounterVec,
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
        // Approximation of Go's per-conn gauge: Pingora pools upstream connections,
        // so this tracks IN-FLIGHT requests per backend addr (inc on upstream
        // selection, dec when the request finishes), not live TCP connections.
        backend_conn: register_int_gauge_vec!(
            "parapet_backend_connections",
            "In-flight requests per backend addr (approximates live connections)",
            &["addr"]
        )
        .expect("register parapet_backend_connections"),
        // Downstream (client-facing) byte totals, matching the parapet framework's
        // prom.Networks counters. NOTE: application/body bytes (the granularity
        // Pingora's Session exposes); Go's net.Conn wrapper counts wire bytes
        // (request/response headers + TLS framing), so these read lower than Go.
        net_request: register_int_counter!(
            "parapet_network_request_bytes",
            "Request body bytes read from downstream"
        )
        .expect("register parapet_network_request_bytes"),
        net_response: register_int_counter!(
            "parapet_network_response_bytes",
            "Response body bytes written downstream"
        )
        .expect("register parapet_network_response_bytes"),
        // TLS handshakes that fell back to the self-signed cert because no loaded
        // cert matched the SNI. A nonzero rate means clients see "unknown
        // authority". `reason`: no_sni | no_match | parse_error (bounded set).
        tls_no_cert: register_int_counter_vec!(
            "parapet_tls_sni_no_cert_total",
            "TLS handshakes served the self-signed fallback (no matching cert)",
            &["reason"]
        )
        .expect("register parapet_tls_sni_no_cert_total"),
    })
}

pub fn tls_no_cert_inc(reason: &str) {
    metrics().tls_no_cert.with_label_values(&[reason]).inc();
}

pub fn backend_read_add(addr: &str, n: u64) {
    metrics().backend_read.with_label_values(&[addr]).inc_by(n);
}

pub fn backend_write_add(addr: &str, n: u64) {
    metrics().backend_write.with_label_values(&[addr]).inc_by(n);
}

pub fn backend_conn_inc(addr: &str) {
    metrics().backend_conn.with_label_values(&[addr]).inc();
}

pub fn backend_conn_dec(addr: &str) {
    metrics().backend_conn.with_label_values(&[addr]).dec();
}

pub fn network_request_add(n: u64) {
    metrics().net_request.inc_by(n);
}

pub fn network_response_add(n: u64) {
    metrics().net_response.inc_by(n);
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

/// Collapse an unrecognized HTTP method to `"other"`. HTTP permits arbitrary
/// method tokens, so without this an attacker could grow the `method` label set
/// without bound (same OOM class as the host label).
fn known_method(method: &str) -> &str {
    const KNOWN: [&str; 9] = [
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE",
    ];
    if KNOWN.contains(&method) {
        method
    } else {
        "other"
    }
}

pub fn record_request(m: &RequestMetric) {
    let metrics = metrics();
    let status = m.status.to_string();
    metrics
        .requests
        .with_label_values(&[
            m.host,
            &status,
            known_method(m.method),
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

#[cfg(test)]
mod tests {
    use super::known_method;

    #[test]
    fn known_method_collapses_unknown() {
        assert_eq!(known_method("GET"), "GET");
        assert_eq!(known_method("DELETE"), "DELETE");
        // arbitrary/extension method tokens collapse to a single label
        assert_eq!(known_method("BREW"), "other");
        assert_eq!(known_method(""), "other");
        assert_eq!(known_method("get"), "other"); // standard methods arrive upper-cased
    }
}
