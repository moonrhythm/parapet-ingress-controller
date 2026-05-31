//! Integration test: a WebSocket (HTTP Upgrade) connection tunnels through the
//! proxy. WebSocket support is entirely Pingora's bidirectional-Upgrade
//! passthrough — the controller adds no WS-specific logic — so this exercises
//! the real binary end-to-end rather than a unit. It runs the built controller
//! as a subprocess in `fs` mode (HTTP-only) routed to a tiny std-only echo
//! "upstream" that completes the Upgrade and echoes bytes.
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

/// Reserve a free localhost port, then release it for the caller to bind.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Minimal WebSocket-ish upstream: complete the Upgrade with `101`, then echo.
fn spawn_echo_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 4096];
                // read request head (until CRLFCRLF)
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
                if s.write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                )
                .is_err()
                {
                    return;
                }
                let _ = s.flush();
                // echo upgraded bytes
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                return;
                            }
                            let _ = s.flush();
                        }
                    }
                }
            });
        }
    });
    port
}

fn write_manifests(dir: &std::path::Path, upstream_port: u16) {
    let yaml = format!(
        "apiVersion: networking.k8s.io/v1\n\
         kind: Ingress\n\
         metadata: {{name: ws, namespace: default}}\n\
         spec:\n  ingressClassName: parapet\n  rules:\n  - host: ws.test\n    http:\n      paths:\n      - path: /\n        pathType: Prefix\n        backend: {{service: {{name: ws, port: {{number: {p}}}}}}}\n\
         ---\n\
         apiVersion: v1\nkind: Service\nmetadata: {{name: ws, namespace: default}}\nspec: {{type: ClusterIP, ports: [{{port: {p}, targetPort: {p}}}]}}\n\
         ---\n\
         apiVersion: v1\nkind: Endpoints\nmetadata: {{name: ws, namespace: default}}\nsubsets: [{{addresses: [{{ip: 127.0.0.1}}], ports: [{{port: {p}}}]}}]\n",
        p = upstream_port
    );
    std::fs::write(dir.join("ws.yaml"), yaml).unwrap();
}

/// Poll `GET /healthz` until the proxy answers 200 (server bound + fs loaded).
fn wait_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(mut c) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = c.set_read_timeout(Some(Duration::from_millis(500)));
            // /healthz is served only for IP hosts (k8s probes the pod IP), so
            // probe with an IP Host, not a domain.
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
fn websocket_upgrade_tunnels_through_proxy() {
    let upstream_port = spawn_echo_upstream();
    let http_port = free_port();

    let dir = std::env::temp_dir().join(format!("parapet-ws-test-{http_port}"));
    std::fs::create_dir_all(&dir).unwrap();
    write_manifests(&dir, upstream_port);

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

    // The tunnel must work at least once. A single attempt is racy on a loaded
    // runner — the upgrade can occasionally be reset right at establishment — so
    // retry the full upgrade+echo exchange within a deadline rather than assert
    // on one shot. A genuinely broken tunnel never succeeds and still fails.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match ws_echo_once(http_port) {
            Ok(()) => break,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "WS upgrade never tunneled within 15s; last error: {e}"
                );
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// One full attempt: connect, upgrade, expect 101, then ping and read the echo
/// back. `Ok(())` only if the whole message tunnels back; any hiccup is `Err`
/// so the caller can retry (transient establishment races) or eventually fail.
fn ws_echo_once(http_port: u16) -> Result<(), String> {
    let mut c = TcpStream::connect(("127.0.0.1", http_port)).map_err(|e| e.to_string())?;
    c.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    c.write_all(
        b"GET /chat HTTP/1.1\r\nHost: ws.test\r\nConnection: Upgrade\r\n\
          Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    )
    .map_err(|e| e.to_string())?;

    // expect 101 Switching Protocols (the upgrade was proxied)
    let mut resp = [0u8; 1024];
    let n = c.read(&mut resp).map_err(|e| e.to_string())?;
    let head = String::from_utf8_lossy(&resp[..n]);
    if !head.contains("101") {
        return Err(format!("expected 101 Switching Protocols, got:\n{head}"));
    }

    // the tunnel is live: bytes echo back through the proxy bidirectionally.
    // Accumulate until the whole message arrives — a single read() can return a
    // partial echo (TCP segmentation through the proxy).
    c.write_all(b"ping-through-proxy")
        .map_err(|e| e.to_string())?;
    let expected: &[u8] = b"ping-through-proxy";
    let mut echo = Vec::new();
    let mut buf = [0u8; 64];
    while echo.len() < expected.len() {
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(m) => echo.extend_from_slice(&buf[..m]),
            Err(e) => return Err(format!("echo read: {e}")),
        }
    }
    if echo == expected {
        Ok(())
    } else {
        Err(format!(
            "echo mismatch: got {:?}",
            String::from_utf8_lossy(&echo)
        ))
    }
}
