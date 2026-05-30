//! Data-plane proxy: optionally run the global WAF (early-drop), then forward to
//! the in-cluster parapet, setting the `X-Forwarded-*` headers parapet trusts
//! (`TRUST_PROXY=<edge CIDR>`) so its authoritative WAF + GeoIP see the true
//! client. The edge is the first hop, so `client_addr` is the real client.
//!
//! The edge WAF is an early-drop optimization; parapet RE-RUNS the full WAF
//! authoritatively (see EDGE.md). A block here just saves the cluster the work.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use controller::waf::{Decision, RequestData};
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use crate::waf::EdgeWaf;

/// The client-facing scheme for this connection: `"https"` when TLS was
/// terminated at this edge (the public TLS listener) and `"http"` when the
/// request arrived on the plaintext `EDGE_HTTP_LISTEN` listener. Detected from
/// the connection's TLS digest, so it's correct regardless of which listener the
/// request came in on. The edge forwards this verbatim as `X-Forwarded-Proto`
/// and does NOT redirect — parapet's `redirect-https` plugin decides http→https.
fn downstream_scheme(session: &Session) -> &'static str {
    let is_tls = session
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .is_some();
    if is_tls {
        "https"
    } else {
        "http"
    }
}

pub struct EdgeProxy {
    /// parapet data-plane address (host:port).
    pub parapet_addr: String,
    /// re-encrypt to parapet (TLS) vs plaintext h2c over a private link.
    pub parapet_tls: bool,
    /// SNI/Host to present to parapet when re-encrypting.
    pub parapet_sni: String,
    /// Global WAF (None = WAF distribution disabled at this edge).
    pub waf: Option<Arc<EdgeWaf>>,
}

impl EdgeProxy {
    /// Build the `request.*` data for WAF evaluation from the live session.
    /// Mirrors the controller's `build_waf_request`. The edge is the first hop, so
    /// `country`/`asn` are resolved from the true client IP (via the edge's own
    /// GeoIP/ASN DBs) — empty/0 when no DB is loaded.
    fn build_waf_request(&self, session: &Session) -> RequestData {
        let req = session.req_header();
        let method = req.method.as_str().to_string();
        // h2 carries the authority in the URI; h1 in the Host header. Prefer the
        // URI authority (present on h2, and absolute-form h1), then fall back to
        // Host — mirrors the controller's host derivation. Reading only Host misses
        // h2 requests (no Host header), which broke host→zone lookup.
        let host = req
            .uri
            .authority()
            .map(|a| a.host().to_string())
            .or_else(|| {
                req.headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.split(':').next().unwrap_or("").to_string())
            })
            .unwrap_or_default()
            .to_ascii_lowercase();
        let path = req.uri.path().to_string();
        let query = req.uri.query().unwrap_or("").to_string();
        let uri = req
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| path.clone());
        let proto = format!("{:?}", req.version);
        // https when TLS was terminated here, http on the plaintext listener — so
        // an edge-evaluated rule on request.scheme sees what parapet will.
        let scheme = downstream_scheme(session).to_string();
        let client_ip = session
            .client_addr()
            .and_then(|a| a.as_inet().map(|i| i.ip()));
        let remote_ip = client_ip.map(|ip| ip.to_string()).unwrap_or_default();
        let (country, asn) = match &self.waf {
            Some(w) => (w.country_of(client_ip), w.asn_of(client_ip)),
            None => (String::new(), 0),
        };
        let content_length = req
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(-1);

        let mut headers = HashMap::new();
        for (name, value) in req.headers.iter() {
            if let Ok(v) = value.to_str() {
                headers
                    .entry(name.as_str().to_ascii_lowercase())
                    .or_insert_with(|| v.to_string());
            }
        }
        let user_agent = headers.get("user-agent").cloned().unwrap_or_default();
        let referer = headers.get("referer").cloned().unwrap_or_default();
        let cookies = parse_cookies(headers.get("cookie").map(String::as_str).unwrap_or(""));
        let args = parse_query_args(&query);

        RequestData {
            method,
            host,
            path,
            query,
            uri,
            proto,
            scheme,
            remote_ip,
            country,
            asn,
            content_length,
            headers,
            cookies,
            args,
            user_agent,
            referer,
            body: String::new(),
        }
    }
}

impl EdgeProxy {
    /// Write a WAF block response (status + plain body) and finish.
    async fn block(session: &mut Session, status: u16, message: String) -> Result<()> {
        let mut resp = pingora::http::ResponseHeader::build(status, None)?;
        resp.insert_header("Content-Length", message.len().to_string())?;
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(bytes::Bytes::from(message.into_bytes())), true)
            .await
    }
}

#[async_trait]
impl ProxyHttp for EdgeProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    /// WAF runs before routing/forwarding. Order mirrors the controller: **global**
    /// (authoritative baseline) first, then the **zone** bound to the request host.
    /// A block short-circuits with the rule's status/message (returns true =
    /// response sent). parapet re-runs the full WAF authoritatively regardless.
    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let Some(waf) = &self.waf else {
            return Ok(false);
        };
        if waf.is_empty() {
            return Ok(false);
        }
        let req = self.build_waf_request(session);

        // 1. global baseline
        if let Decision::Block { status, message } = waf.evaluate_global(&req, |_, _| {}) {
            return Self::block(session, status, message).await.map(|()| true);
        }
        // 2. zone bound to this host (host-level; path precision is parapet's job)
        if let Decision::Block { status, message } = waf.evaluate_zone(&req.host, &req, |_, _| {}) {
            return Self::block(session, status, message).await.map(|()| true);
        }
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(
            self.parapet_addr.as_str(),
            self.parapet_tls,
            self.parapet_sni.clone(),
        )))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream: &mut pingora::http::RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream.insert_header("x-forwarded-proto", downstream_scheme(session))?;
        let client_ip = session
            .client_addr()
            .and_then(|a| a.as_inet().map(|i| i.ip()));
        if let Some(ip) = client_ip {
            let ip = ip.to_string();
            upstream.insert_header("x-forwarded-for", ip.as_str())?;
            upstream.insert_header("x-real-ip", ip.as_str())?;
        }
        // Forward the GeoIP/ASN the edge resolved from the true client IP,
        // overwriting any client-supplied value so parapet can trust them (matches
        // the controller's upstream behavior). Only when a DB is loaded.
        if let Some(waf) = &self.waf {
            let country = waf.country_of(client_ip);
            if !country.is_empty() {
                upstream.insert_header("x-forwarded-country", country.as_str())?;
            }
            let asn = waf.asn_of(client_ip);
            if asn != 0 {
                upstream.insert_header("x-forwarded-asn", asn.to_string())?;
            }
        }
        Ok(())
    }
}

/// `k=v; k2=v2` → map (first value wins), mirroring the controller's parse_cookies.
fn parse_cookies(s: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for part in s.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            m.entry(k.trim().to_string())
                .or_insert_with(|| v.trim().to_string());
        }
    }
    m
}

/// `a=1&b=2` → map of first values, URL-decoded, mirroring the controller.
fn parse_query_args(query: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        m.entry(url_decode(k)).or_insert_with(|| url_decode(v));
    }
    m
}

/// Minimal `application/x-www-form-urlencoded` decode: `+`→space, `%XX`→byte.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
