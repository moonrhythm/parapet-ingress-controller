//! Integration: `HOST_CONCURRENT_CAPACITY` releases its slot when upstream
//! response headers arrive (matches Go's `ReleaseOnWriteHeader`). Regression
//! test for the SSE / long-lived-stream case where a slot would otherwise
//! stay pinned for the entire stream lifetime, exhausting the per-host cap
//! with no DDoS actually happening.
//!
//! Strategy: spin up the real binary in `fs` mode with `HOST_CONCURRENT_CAPACITY=1`
//! and `HOST_CONCURRENT_SIZE=0` (no queue, immediate-reject). A slow upstream
//! sends `200 OK text/event-stream` headers + one chunked event, then holds
//! the connection open. We read the headers on conn 1 (which is only possible
//! after `response_filter` has run on the proxy), then open conn 2 to the
//! same host. Pre-fix: conn 2 returns `503` because the slot is still held
//! by conn 1's still-streaming body. Post-fix: the slot was released on
//! headers, so conn 2 is admitted.
//!
//! Only built with `proxy,cluster`; a no-op otherwise.
#![cfg(all(feature = "proxy", feature = "cluster"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

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

/// SSE-like upstream: send `200 OK text/event-stream` + one chunked event,
/// then hold the connection open without sending more. The proxy sees a
/// long-lived streaming body, which is the case that used to pin the slot.
fn spawn_sse_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 4096];
                let mut head = Vec::new();
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                // chunk body is "data: hi\n" (9 bytes) framed as one chunk;
                // no terminating 0-chunk, so the body stays open.
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: text/event-stream\r\n\
                      Cache-Control: no-cache\r\n\
                      Transfer-Encoding: chunked\r\n\r\n\
                      9\r\ndata: hi\n\r\n",
                );
                let _ = s.flush();
                // Park the stream so the body stays open for the duration of
                // the test. The controller subprocess is killed on test exit,
                // which closes its end and unblocks this thread.
                let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
                let _ = s.read(&mut buf);
            });
        }
    });
    port
}

fn write_manifests(dir: &std::path::Path, upstream_port: u16, host: &str) {
    let yaml = format!(
        "apiVersion: networking.k8s.io/v1\n\
         kind: Ingress\n\
         metadata: {{name: sse, namespace: default}}\n\
         spec:\n  ingressClassName: parapet\n  rules:\n  - host: {host}\n    http:\n      paths:\n      - path: /\n        pathType: Prefix\n        backend: {{service: {{name: sse, port: {{number: {p}}}}}}}\n\
         ---\n\
         apiVersion: v1\nkind: Service\nmetadata: {{name: sse, namespace: default}}\nspec: {{type: ClusterIP, ports: [{{port: {p}, targetPort: {p}}}]}}\n\
         ---\n\
         apiVersion: v1\nkind: Endpoints\nmetadata: {{name: sse, namespace: default}}\nsubsets: [{{addresses: [{{ip: 127.0.0.1}}], ports: [{{port: {p}}}]}}]\n",
        p = upstream_port,
        host = host,
    );
    std::fs::write(dir.join("sse.yaml"), yaml).unwrap();
}

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

/// Read until either headers (\r\n\r\n) are seen or the read times out / EOFs.
fn read_response_head(c: &mut TcpStream) -> String {
    let mut acc = Vec::new();
    let mut buf = [0u8; 1024];
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                acc.extend_from_slice(&buf[..n]);
                if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    String::from_utf8_lossy(&acc).to_string()
}

#[test]
fn host_cap_releases_slot_on_response_headers() {
    let upstream_port = spawn_sse_upstream();
    let http_port = free_port();

    let dir = std::env::temp_dir().join(format!("parapet-sse-cap-test-{http_port}"));
    std::fs::create_dir_all(&dir).unwrap();
    write_manifests(&dir, upstream_port, "sse.test");

    let child = Command::new(env!("CARGO_BIN_EXE_parapet-ingress-controller"))
        .env("KUBERNETES_BACKEND", "fs")
        .env("KUBERNETES_FS", &dir)
        .env("HTTP_PORT", http_port.to_string())
        .env("HTTPS_PORT", "")
        .env("DISABLE_LOG", "true")
        // capacity=1, no queue: any second concurrent request is immediately
        // 503'd unless the first one released its slot before #2's acquire.
        .env("HOST_CONCURRENT_CAPACITY", "1")
        .env("HOST_CONCURRENT_SIZE", "0")
        .spawn()
        .expect("spawn controller binary");
    let _ctrl = Controller(child);

    wait_ready(http_port);

    // conn 1: open the SSE stream. Reading the response head proves the
    // proxy has run `response_filter` (where the guard is released).
    let mut c1 = TcpStream::connect(("127.0.0.1", http_port)).unwrap();
    c1.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c1.write_all(b"GET /events HTTP/1.1\r\nHost: sse.test\r\nAccept: text/event-stream\r\n\r\n")
        .unwrap();
    let resp1 = read_response_head(&mut c1);
    assert!(
        resp1.contains("200 OK") && resp1.to_lowercase().contains("text/event-stream"),
        "expected 200 OK SSE on conn 1, got:\n{resp1}"
    );

    // conn 2: while conn 1's body is still streaming, a second request to the
    // same host. Pre-fix this was rejected with 503; post-fix it must be admitted.
    let mut c2 = TcpStream::connect(("127.0.0.1", http_port)).unwrap();
    c2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c2.write_all(
        b"GET /events HTTP/1.1\r\nHost: sse.test\r\n\
          Accept: text/event-stream\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    let resp2 = read_response_head(&mut c2);
    assert!(
        !resp2.contains("503"),
        "got 503 on conn 2 — host concurrency slot was not released on response headers:\n{resp2}"
    );
    assert!(
        resp2.contains("200 OK"),
        "expected 200 OK on conn 2 (slot should release on conn 1's headers), got:\n{resp2}"
    );

    drop(c1);
    drop(c2);
    let _ = std::fs::remove_dir_all(&dir);
}
