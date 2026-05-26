//! Integration test: `/healthz` is served **only when the request is addressed
//! to an IP** (k8s probes hit the pod IP). A request with a domain Host falls
//! through to normal routing instead of hitting the controller's health check —
//! so external callers can't probe health and a backend's own `/healthz` is
//! reachable. Mirrors parapet's healthz `Host: false` semantics. Runs the built
//! controller as a subprocess in `fs` mode (HTTP-only).
//!
//! Only built with `proxy,cluster` (the binary's required-features); a no-op
//! otherwise.
#![cfg(all(feature = "proxy", feature = "cluster"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

/// Kill the child controller on drop so a failed assertion never leaks it.
struct Controller(Child);
impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Send `GET {target}` with the given Host header, return the status line.
fn status_line(port: u16, target: &str, host: &str) -> String {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let req = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    c.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    let _ = c.read_to_end(&mut resp);
    String::from_utf8_lossy(&resp)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Poll `/healthz` (with an IP Host, the only one served) until ready, tolerating
/// connection failures while the controller is still binding.
fn wait_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(mut c) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = c.set_read_timeout(Some(Duration::from_millis(500)));
            if c.write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .is_ok()
            {
                let mut resp = Vec::new();
                let _ = c.read_to_end(&mut resp);
                if String::from_utf8_lossy(&resp).contains("200") {
                    return;
                }
            }
        }
        thread::sleep(Duration::from_millis(150));
    }
    panic!("controller did not become ready on :{port}");
}

#[test]
fn healthz_served_only_on_ip_host() {
    let http_port = free_port();
    let dir = std::env::temp_dir().join(format!("parapet-healthz-test-{http_port}"));
    std::fs::create_dir_all(&dir).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_parapet-ingress-controller"))
        .env("KUBERNETES_BACKEND", "fs")
        .env("KUBERNETES_FS", &dir)
        .env("HTTP_PORT", http_port.to_string())
        .env("HTTPS_PORT", "") // HTTP-only (empty disables HTTPS)
        .env("DISABLE_LOG", "true")
        .spawn()
        .expect("spawn controller binary");
    let _ctrl = Controller(child);

    wait_ready(http_port);

    // IP Host (k8s probe style): liveness + readiness are served.
    assert!(
        status_line(http_port, "/healthz", "127.0.0.1").contains(" 200 "),
        "liveness on IP host should be 200"
    );
    assert!(
        status_line(http_port, "/healthz?ready=1", "127.0.0.1").contains(" 200 "),
        "readiness on IP host should be 200"
    );

    // Domain Host: NOT intercepted — falls through to routing. No route is
    // configured, so it 404s (the point: it is not the health check's 200).
    let domain = status_line(http_port, "/healthz", "app.example.com");
    assert!(
        domain.contains(" 404 "),
        "/healthz on a domain host must route normally (404 here), got: {domain:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
