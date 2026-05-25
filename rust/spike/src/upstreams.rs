// Minimal in-process test upstreams (hyper 1.x) so the spike can prove proxying
// end-to-end without external services. Each runs on its own thread + runtime.
// The response body echoes the HTTP version the upstream actually saw, which is
// how we confirm h2c (cleartext HTTP/2) really reached the backend.

use std::convert::Infallible;

use bytes::Bytes;
use http::{header, HeaderName, HeaderValue, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn handle(
    tag: &'static str,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = format!(
        "upstream={} version={:?} path={}",
        tag,
        req.version(),
        req.uri().path()
    );
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    resp.headers_mut().insert(
        HeaderName::from_static("x-upstream"),
        HeaderValue::from_static(tag),
    );
    Ok(resp)
}

fn run<F>(addr: &'static str, serve: F)
where
    F: Fn(TokioIo<tokio::net::TcpStream>, &'static str) + Copy + Send + 'static,
{
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let l = TcpListener::bind(addr).await.unwrap();
            loop {
                let (s, _) = l.accept().await.unwrap();
                serve(TokioIo::new(s), addr);
            }
        });
    });
}

/// HTTP/1.1 upstream (also accepts Upgrade for websocket passthrough tests).
pub fn spawn_h1(addr: &'static str, tag: &'static str) {
    run(addr, move |io, _| {
        tokio::task::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service_fn(move |r| handle(tag, r)))
                .with_upgrades()
                .await;
        });
    });
}

/// h2c upstream: HTTP/2 over cleartext TCP (prior knowledge, no TLS).
pub fn spawn_h2c(addr: &'static str, tag: &'static str) {
    run(addr, move |io, _| {
        tokio::task::spawn(async move {
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, service_fn(move |r| handle(tag, r)))
                .await;
        });
    });
}

/// Reply 101 to an Upgrade request, then echo bytes on the upgraded connection
/// (a stand-in for a websocket backend, to prove Upgrade passthrough).
async fn ws_echo(mut req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if !req.headers().contains_key(header::UPGRADE) {
        return Ok(Response::new(Full::new(Bytes::from("not an upgrade"))));
    }
    let on = hyper::upgrade::on(&mut req);
    tokio::task::spawn(async move {
        if let Ok(upgraded) = on.await {
            let mut io = TokioIo::new(upgraded);
            let mut buf = [0u8; 1024];
            while let Ok(n) = io.read(&mut buf).await {
                if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    });
    let resp = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .body(Full::new(Bytes::new()))
        .unwrap();
    Ok(resp)
}

pub fn spawn_ws(addr: &'static str) {
    run(addr, move |io, _| {
        tokio::task::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service_fn(ws_echo))
                .with_upgrades()
                .await;
        });
    });
}
