//! The Pingora `ProxyHttp` implementation: routing, upstream selection
//! (http/https/h2c) with retry + bad-addr skip, per-route middleware, trust-proxy
//! / X-Forwarded-* handling, the JSON access log, and request metrics. Mirrors
//! the Go controller's request path.

pub mod cert;
pub mod limit;
pub mod metrics;
pub mod predefined;
pub mod procmetrics;
pub mod ratelimit;
pub mod server;

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use chrono::{SecondsFormat, Utc};
use ipnet::IpNet;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::modules::http::compression::{ResponseCompression, ResponseCompressionBuilder};
use pingora::modules::http::HttpModules;
use pingora::protocols::ALPN;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorType, Result};
use serde_json::{Map, Value};

use self::limit::{Guard, HostConcurrency};
use crate::config::{
    single_joining_slash, BasicAuth, ForwardAuth, Hsts, RouteConfig, UpstreamProtocol,
};
use crate::reconcile::{RouteKind, RouteMeta};
use crate::router::Match;
use crate::shared::Shared;

const MAX_RETRY: usize = 5;
const ACME_PREFIX: &str = "/.well-known/acme-challenge";

/// Which downstream remotes are trusted to set X-Forwarded-* headers.
pub enum TrustProxy {
    None,
    All,
    Cidrs(Vec<IpNet>),
}

impl TrustProxy {
    /// Parse the TRUST_PROXY env value: `true` / `false` / a comma-separated list
    /// of CIDRs and/or predefined shorthands (`cloudflare`, `google`, `bunny`),
    /// which expand to their CIDR lists. Mirrors the Go config parsing.
    pub fn parse(s: &str) -> Self {
        match s.trim() {
            "true" => Self::All,
            "" | "false" => Self::None,
            other => {
                let mut nets = Vec::new();
                for tok in other.split(',') {
                    let tok = tok.trim();
                    if let Some(list) = predefined::predefined(tok) {
                        nets.extend(list.iter().filter_map(|c| c.parse::<IpNet>().ok()));
                    } else if let Ok(n) = tok.parse::<IpNet>() {
                        nets.push(n);
                    }
                }
                Self::Cidrs(nets)
            }
        }
    }

    fn trusts(&self, ip: IpAddr) -> bool {
        match self {
            Self::None => false,
            Self::All => true,
            Self::Cidrs(nets) => nets.iter().any(|n| n.contains(&ip)),
        }
    }
}

/// Global (non-per-route) host concurrency limits, configured from env.
#[derive(Default)]
pub struct Limits {
    pub host: Option<Arc<HostConcurrency>>,
    pub country: Option<Arc<HostConcurrency>>,
    pub country_headers: Vec<String>,
}

pub struct Proxy {
    shared: Arc<Shared>,
    is_tls: bool,
    trust: Arc<TrustProxy>,
    limits: Arc<Limits>,
    log_enabled: bool,
    /// When set (DEBUG_ENDPOINTS=true), serves GET /debug/routes.
    debug: bool,
}

impl Proxy {
    pub fn new(
        shared: Arc<Shared>,
        is_tls: bool,
        trust: Arc<TrustProxy>,
        limits: Arc<Limits>,
        log_enabled: bool,
        debug: bool,
    ) -> Self {
        Self {
            shared,
            is_tls,
            trust,
            limits,
            log_enabled,
            debug,
        }
    }
}

#[derive(Default)]
pub struct Ctx {
    // routing / upstream
    target: Option<String>,
    protocol: String,
    config: Option<Arc<RouteConfig>>,
    tries: usize,
    last_addr: Option<String>,
    /// Addr currently counted in the backend in-flight gauge (so retries move it
    /// and `logging` decrements exactly once). Distinct from `last_addr`.
    backend_conn_addr: Option<String>,
    // access log / metrics
    start: Option<Instant>,
    timestamp: String,
    method: String,
    host: String,
    request_url: String,
    request_body_size: i64,
    referer: String,
    user_agent: String,
    remote_ip: String,
    real_ip: String,
    forwarded_for: String,
    meta: RouteMeta,
    pattern: String,
    skip_log: bool,
    // host concurrency
    limit_guards: Vec<Guard>,
    host_active: Option<(String, String)>,
    // forward-auth response headers to copy upstream
    auth_response_headers: Vec<(String, String)>,
}

enum Decision {
    Proceed,
    NotFound,
    Redirect(u16, String),
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx::default()
    }

    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        // gzip + brotli (quality 4), negotiated via Accept-Encoding
        modules.add_module(ResponseCompressionBuilder::enable(4));
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        let scheme = if self.is_tls { "https" } else { "http" };
        let remote_ip = client_ip(session);

        // trust-proxy / X-Forwarded-* (parapet proxy middleware)
        self.apply_forwarded_headers(session, remote_ip, scheme);

        let host = req_host(session);
        let path = session.req_header().uri.path().to_string();

        // capture access-log fields up front
        ctx.start = Some(Instant::now());
        ctx.timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        ctx.remote_ip = remote_ip.map(|i| i.to_string()).unwrap_or_default();
        ctx.capture(session, &host, scheme);

        // health checks (run before logging, like the Go middleware order)
        if path == "/healthz" {
            ctx.skip_log = true;
            let want_ready = session
                .req_header()
                .uri
                .query()
                .is_some_and(|q| q.split('&').any(|kv| kv == "ready=1"));
            let code = if want_ready && !self.shared.is_ready() {
                503
            } else {
                200
            };
            respond_status(session, code).await?;
            return Ok(true);
        }

        // debug introspection: what's actually loaded (route keys + cert SNIs)
        if self.debug && path == "/debug/routes" {
            ctx.skip_log = true;
            let body = {
                let router = self.shared.router.load();
                let certs = self.shared.certs.load();
                let mut routes = router.patterns();
                routes.sort_unstable();
                let mut snis = certs.names();
                snis.sort_unstable();
                format!(
                    "ready={}\nroutes={}\ncert_snis={}\n--- routes (host+path) ---\n{}\n--- cert SNIs ---\n{}\n",
                    self.shared.is_ready(),
                    routes.len(),
                    snis.len(),
                    routes.join("\n"),
                    snis.join("\n"),
                )
            };
            respond_with_body(session, 200, body.into_bytes()).await?;
            return Ok(true);
        }

        // host concurrency limits (parapet HostActiveTracker + host/country rate
        // limit middlewares run before routing/logging). On reject: 503, counted
        // in host_ratelimit, and not access-logged.
        let upgrade = header_str(session, "upgrade")
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        metrics::host_active_inc(&host, &upgrade);
        ctx.host_active = Some((host.clone(), upgrade));

        if let Some(country_limit) = &self.limits.country {
            let country = self
                .limits
                .country_headers
                .iter()
                .find_map(|h| header_str(session, h))
                .filter(|s| !s.is_empty())
                .unwrap_or("XX");
            match country_limit.acquire(&format!("{host}|{country}")).await {
                Some(g) => ctx.limit_guards.push(g),
                None => return self.reject_overloaded(session, ctx, &host).await,
            }
        }
        if let Some(host_limit) = &self.limits.host {
            match host_limit.acquire(&host).await {
                Some(g) => ctx.limit_guards.push(g),
                None => return self.reject_overloaded(session, ctx, &host).await,
            }
        }

        let decision = {
            let router = self.shared.router.load();
            match router.lookup(&host, &path) {
                Match::NotFound => Decision::NotFound,
                Match::Redirect(loc) => Decision::Redirect(301, loc),
                Match::Found(entry) => match &entry.kind {
                    RouteKind::Redirect { status, target } => {
                        Decision::Redirect(*status, target.clone())
                    }
                    RouteKind::Service { target, protocol } => {
                        ctx.target = Some(target.clone());
                        ctx.protocol = protocol.clone();
                        ctx.config = Some(entry.config.clone());
                        ctx.meta = entry.meta.clone();
                        ctx.pattern = entry.pattern.clone();
                        Decision::Proceed
                    }
                },
            }
        };

        match decision {
            Decision::NotFound => {
                respond_status(session, 404).await?;
                Ok(true)
            }
            Decision::Redirect(code, location) => {
                respond_redirect(session, code, &location).await?;
                Ok(true)
            }
            Decision::Proceed => self.apply_route_filters(session, &host, &path, ctx).await,
        }
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        let target = ctx
            .target
            .as_deref()
            .ok_or_else(|| Error::explain(ErrorType::HTTPStatus(404), "no route"))?;

        let addr = self.shared.route_table.lookup(target);
        if addr.is_empty() {
            return Err(Error::explain(
                ErrorType::HTTPStatus(503),
                "service unavailable",
            ));
        }
        ctx.last_addr = Some(addr.clone());

        // backend in-flight gauge: move it to the new addr on a retry; `logging`
        // decrements the final one. Keeps inc/dec balanced across retries.
        if ctx.backend_conn_addr.as_deref() != Some(addr.as_str()) {
            if let Some(prev) = ctx.backend_conn_addr.take() {
                metrics::backend_conn_dec(&prev);
            }
            metrics::backend_conn_inc(&addr);
            ctx.backend_conn_addr = Some(addr.clone());
        }

        let peer = match effective_protocol(ctx) {
            EffProto::H2c => {
                let mut p = HttpPeer::new(addr.as_str(), false, String::new());
                p.options.alpn = ALPN::H2;
                p
            }
            EffProto::Https => {
                let mut p = HttpPeer::new(addr.as_str(), true, String::new());
                p.options.alpn = ALPN::H2H1;
                p.options.verify_cert = false;
                p.options.verify_hostname = false;
                p
            }
            EffProto::Http => {
                let mut p = HttpPeer::new(addr.as_str(), false, String::new());
                p.options.alpn = ALPN::H1;
                p
            }
        };
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream: &mut RequestHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let Some(cfg) = ctx.config.clone() else {
            return Ok(());
        };

        if let Some(h) = &cfg.upstream_host {
            let _ = upstream.insert_header("host", h.as_str());
        }

        // copy headers returned by forward-auth onto the upstream request
        for (name, value) in &ctx.auth_response_headers {
            if let Ok(hn) = http::header::HeaderName::from_bytes(name.as_bytes()) {
                let _ = upstream.insert_header(hn, value.as_str());
            }
        }

        let (path, query) = rewrite_path_query(upstream.uri.path(), upstream.uri.query(), &cfg);
        let pq = match &query {
            Some(q) => format!("{path}?{q}"),
            None => path,
        };
        // Replace only the path-and-query; preserve scheme + authority. Rebuilding
        // the URI as path-only would strip the authority, which an HTTP/2 (h2c)
        // upstream needs as `:authority` — when the downstream is also HTTP/2 there
        // is no Host header to fall back on, so it fails with "no authority header
        // for h2".
        if let Ok(new_pq) = pq.parse::<http::uri::PathAndQuery>() {
            let mut parts = upstream.uri.clone().into_parts();
            parts.path_and_query = Some(new_pq);
            if let Ok(uri) = http::Uri::from_parts(parts) {
                upstream.set_uri(uri);
            }
        }
        Ok(())
    }

    // parapet_backend_network_write_bytes: request body bytes forwarded to the
    // backend, keyed by pod addr. (Body only — headers aren't visible here.)
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Ctx,
    ) -> Result<()> {
        if let (Some(b), Some(addr)) = (body.as_ref(), ctx.last_addr.as_deref()) {
            if !b.is_empty() {
                metrics::backend_write_add(addr, b.len() as u64);
            }
        }
        Ok(())
    }

    // parapet_backend_network_read_bytes: response body bytes received from the
    // backend (pre-downstream-compression), keyed by pod addr.
    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Ctx,
    ) -> Result<Option<Duration>> {
        if let (Some(b), Some(addr)) = (body.as_ref(), ctx.last_addr.as_deref()) {
            if !b.is_empty() {
                metrics::backend_read_add(addr, b.len() as u64);
            }
        }
        Ok(None)
    }

    // NOTE: no upstream_response_filter retry. We deliberately do NOT retry based
    // on the upstream's HTTP status (even 502/503): once the upstream *responds*
    // it has received and processed the request, so retrying could duplicate
    // side effects and just amplifies load on a struggling backend. Retries
    // happen only on connection failures: `fail_to_connect` (cannot connect) and
    // Pingora's default `error_while_proxy` (a reused/keepalive connection breaks
    // before a response, with a replayable body). (Go's controller also retried
    // 502/503 via IsRetryable; this is an intentional divergence.)

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        // Server-Sent Events: Pingora's compressor treats text/event-stream as
        // compressible (it matches the `text/*` allowlist) and buffers it instead
        // of flushing per event, which stalls the stream in the browser. Disable
        // compression for this response. Must happen in the header phase —
        // adjust_level panics once the body phase has begun.
        if is_event_stream(upstream_response) {
            if let Some(c) = session
                .downstream_modules_ctx
                .get_mut::<ResponseCompression>()
            {
                c.adjust_level(0);
            }
        }

        if let Some(cfg) = &ctx.config {
            if let Some(hsts) = &cfg.hsts {
                let value = match hsts {
                    Hsts::Preload => "max-age=63072000; includeSubDomains; preload",
                    Hsts::Default => "max-age=31536000",
                };
                let _ = upstream_response.insert_header("Strict-Transport-Security", value);
            }
        }
        Ok(())
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Ctx,
        mut e: Box<Error>,
    ) -> Box<Error> {
        if let Some(addr) = &ctx.last_addr {
            self.shared.route_table.mark_bad(addr);
        }
        ctx.tries += 1;
        if ctx.tries < MAX_RETRY {
            e.set_retry(true);
        }
        e
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Ctx) {
        // always release the host-active + backend in-flight gauges
        if let Some((host, upgrade)) = &ctx.host_active {
            metrics::host_active_dec(host, upgrade);
        }
        if let Some(addr) = ctx.backend_conn_addr.take() {
            metrics::backend_conn_dec(&addr);
        }
        // surface the upstream failure cause (otherwise only a bare 502 is visible)
        if let Some(e) = e {
            eprintln!(
                "[proxy-error] host={} target={:?} proto={} tries={} err={}",
                ctx.host, ctx.last_addr, ctx.protocol, ctx.tries, e
            );
        }
        if ctx.skip_log {
            return;
        }
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);
        let duration = ctx.start.map(|s| s.elapsed()).unwrap_or_default();

        metrics::record_request(&metrics::RequestMetric {
            host: &ctx.host,
            status,
            method: &ctx.method,
            ingress_name: &ctx.meta.ingress_name,
            ingress_namespace: &ctx.meta.ingress_namespace,
            service_type: &ctx.meta.service_type,
            service_name: &ctx.meta.service_name,
            duration_secs: duration.as_secs_f64(),
        });

        // Downstream byte totals (parapet prom.Networks parity), counted once per
        // request from the session's app-level body byte counters.
        metrics::network_request_add(session.body_bytes_read() as u64);
        metrics::network_response_add(session.body_bytes_sent() as u64);

        if self.log_enabled {
            let body_sent = session.body_bytes_sent() as i64;
            let mut m = Map::new();
            put_str(&mut m, "timestamp", &ctx.timestamp);
            put_str(&mut m, "host", &ctx.host);
            put_str(&mut m, "requestMethod", &ctx.method);
            put_str(&mut m, "requestUrl", &ctx.request_url);
            if ctx.request_body_size > 0 {
                m.insert("requestBodySize".into(), ctx.request_body_size.into());
            }
            put_str(&mut m, "referer", &ctx.referer);
            put_str(&mut m, "userAgent", &ctx.user_agent);
            put_str(&mut m, "remoteIp", &ctx.remote_ip);
            put_str(&mut m, "realIp", &ctx.real_ip);
            put_str(&mut m, "forwardedFor", &ctx.forwarded_for);
            m.insert("duration".into(), (duration.as_nanos() as i64).into());
            m.insert("durationHuman".into(), Value::from(format!("{duration:?}")));
            m.insert("status".into(), status.into());
            if body_sent > 0 {
                m.insert("responseBodySize".into(), body_sent.into());
            }
            put_str(&mut m, "namespace", &ctx.meta.ingress_namespace);
            put_str(&mut m, "ingress", &ctx.meta.ingress_name);
            put_str(&mut m, "serviceName", &ctx.meta.service_name);
            put_str(&mut m, "serviceType", &ctx.meta.service_type);
            if let Some(t) = &ctx.last_addr {
                put_str(&mut m, "serviceTarget", t);
            }
            println!("{}", Value::Object(m));
        }
    }
}

impl Proxy {
    /// Per-route request-side middleware, in the Go chain order. Returns `true`
    /// when a filter has answered the request (proxying should stop).
    async fn apply_route_filters(
        &self,
        session: &mut Session,
        host: &str,
        path: &str,
        ctx: &mut Ctx,
    ) -> Result<bool> {
        let Some(cfg) = ctx.config.clone() else {
            return Ok(false);
        };
        let is_acme = path.starts_with(ACME_PREFIX);

        if !cfg.allow_remote.is_empty() && !is_acme {
            let allowed = client_ip(session)
                .is_some_and(|ip| cfg.allow_remote.iter().any(|net| net.contains(&ip)));
            if !allowed {
                respond_status(session, 403).await?;
                return Ok(true);
            }
        }

        if cfg.redirect_https && !is_acme && !self.is_https(session) {
            let pq = session
                .req_header()
                .uri
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/")
                .to_string();
            respond_redirect(session, 301, &format!("https://{host}{pq}")).await?;
            return Ok(true);
        }

        // rate limits (fixed window per second/minute/hour)
        let rl = ratelimit::windows();
        let over = |id: u8, limit: Option<u32>, period: Duration| -> bool {
            limit.is_some_and(|n| !rl.allow(&ctx.pattern, id, n, period))
        };
        if over(0, cfg.ratelimit_s, Duration::from_secs(1))
            || over(1, cfg.ratelimit_m, Duration::from_secs(60))
            || over(2, cfg.ratelimit_h, Duration::from_secs(3600))
        {
            respond_status(session, 429).await?;
            return Ok(true);
        }

        if let Some(limit) = cfg.body_limit {
            if content_length(session).is_some_and(|cl| cl > limit as u64) {
                respond_status(session, 413).await?;
                return Ok(true);
            }
        }

        if let Some(ba) = &cfg.basic_auth {
            if !check_basic_auth(session, ba) {
                let mut resp = ResponseHeader::build(401, None)?;
                resp.insert_header("WWW-Authenticate", "Basic realm=\"Restricted\"")?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }
        }

        // forward-auth: delegate to an external authorizer
        if let Some(fa) = &cfg.forward_auth {
            match forward_auth(session, fa, host).await {
                ForwardAuthOutcome::Allow(headers) => ctx.auth_response_headers = headers,
                ForwardAuthOutcome::Deny(code, body) => {
                    respond_with_body(session, code, body).await?;
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn is_https(&self, session: &Session) -> bool {
        self.is_tls || header_str(session, "x-forwarded-proto") == Some("https")
    }

    async fn reject_overloaded(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        host: &str,
    ) -> Result<bool> {
        metrics::host_ratelimit_inc(host);
        ctx.skip_log = true; // ratelimited responses aren't access-logged (Go order)
        respond_status(session, 503).await?;
        Ok(true)
    }

    /// Set X-Forwarded-For/-Proto and X-Real-Ip per the trust policy, so the
    /// upstream (and our access log) see consistent client info. Mirrors
    /// parapet's proxy trust/distrust handling.
    fn apply_forwarded_headers(
        &self,
        session: &mut Session,
        remote_ip: Option<IpAddr>,
        scheme: &str,
    ) {
        let remote = remote_ip.map(|i| i.to_string()).unwrap_or_default();
        let trusted = remote_ip.is_some_and(|ip| self.trust.trusts(ip));
        let h = session.req_header_mut();

        if trusted {
            if h.headers.get("x-real-ip").is_none() {
                let first = {
                    let xff = h
                        .headers
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    xff.split(',').next().unwrap_or("").trim().to_string()
                };
                let _ = h.insert_header("x-real-ip", first);
            }
            if h.headers.get("x-forwarded-proto").is_none() {
                let _ = h.insert_header("x-forwarded-proto", scheme);
            }
        } else {
            let _ = h.insert_header("x-forwarded-for", remote.as_str());
            let _ = h.insert_header("x-real-ip", remote.as_str());
            let _ = h.insert_header("x-forwarded-proto", scheme);
        }
    }
}

impl Ctx {
    fn capture(&mut self, session: &Session, host: &str, scheme: &str) {
        let req = session.req_header();
        self.method = req.method.to_string();
        self.host = host.to_string();
        let pq = req.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        self.request_url = format!("{scheme}://{host}{pq}");
        self.request_body_size = content_length(session).map(|c| c as i64).unwrap_or(-1);
        self.referer = header_str(session, "referer")
            .unwrap_or_default()
            .to_string();
        self.user_agent = header_str(session, "user-agent")
            .unwrap_or_default()
            .to_string();
        self.real_ip = header_str(session, "x-real-ip")
            .unwrap_or_default()
            .to_string();
        self.forwarded_for = header_str(session, "x-forwarded-for")
            .unwrap_or_default()
            .to_string();
    }
}

enum EffProto {
    Http,
    Https,
    H2c,
}

fn effective_protocol(ctx: &Ctx) -> EffProto {
    match ctx.protocol.as_str() {
        "h2c" => EffProto::H2c,
        "https" => EffProto::Https,
        "" => match ctx.config.as_ref().map(|c| &c.upstream_protocol) {
            Some(UpstreamProtocol::Https) => EffProto::Https,
            _ => EffProto::Http,
        },
        _ => EffProto::Http,
    }
}

/// True when the response Content-Type is `text/event-stream` (SSE), ignoring
/// any `; charset=...` suffix and case.
fn is_event_stream(resp: &ResponseHeader) -> bool {
    resp.headers
        .get(http::header::CONTENT_TYPE)
        .map(|v| {
            v.as_bytes()
                .split(|&b| b == b';')
                .next()
                .unwrap_or(b"")
                .trim_ascii()
                .eq_ignore_ascii_case(b"text/event-stream")
        })
        .unwrap_or(false)
}

fn req_host(session: &Session) -> String {
    let req = session.req_header();
    if let Some(h) = req.uri.host() {
        return h.to_ascii_lowercase();
    }
    if let Some(v) = req.headers.get(http::header::HOST) {
        if let Ok(s) = v.to_str() {
            return s.split(':').next().unwrap_or(s).to_ascii_lowercase();
        }
    }
    String::new()
}

fn client_ip(session: &Session) -> Option<IpAddr> {
    session
        .client_addr()
        .and_then(|a| a.as_inet())
        .map(|s| s.ip())
}

fn content_length(session: &Session) -> Option<u64> {
    header_str(session, "content-length")?.trim().parse().ok()
}

fn header_str<'a>(session: &'a Session, name: &str) -> Option<&'a str> {
    session.req_header().headers.get(name)?.to_str().ok()
}

fn check_basic_auth(session: &Session, ba: &BasicAuth) -> bool {
    basic_auth_ok(header_str(session, "authorization"), ba)
}

/// Validate an `Authorization: Basic <b64(user:pass)>` header value against the
/// configured credentials (constant-time compare). Pure, so it's unit-testable.
fn basic_auth_ok(authorization: Option<&str>, ba: &BasicAuth) -> bool {
    let Some(token) = authorization.and_then(|h| h.strip_prefix("Basic ")) else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token.trim()) else {
        return false;
    };
    let Ok(creds) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((user, pass)) = creds.split_once(':') else {
        return false;
    };
    ct_eq(user.as_bytes(), ba.user.as_bytes()) & ct_eq(pass.as_bytes(), ba.pass.as_bytes())
}

/// Compute the upstream path + query from the incoming request and route config:
/// prepend `upstream-path` (merging its query), then strip `strip-prefix`. Pure
/// so the path-rewriting rules (a frequent source of prod 404s) are unit-tested;
/// the caller splices the result into the URI preserving scheme + authority.
fn rewrite_path_query(
    path: &str,
    query: Option<&str>,
    cfg: &RouteConfig,
) -> (String, Option<String>) {
    let mut path = path.to_string();
    let mut query = query.map(str::to_string);

    if let Some(up) = &cfg.upstream_path {
        path = single_joining_slash(&up.path, &path);
        let existing = query.clone().unwrap_or_default();
        let merged = if up.raw_query.is_empty() || existing.is_empty() {
            format!("{}{}", up.raw_query, existing)
        } else {
            format!("{}&{}", up.raw_query, existing)
        };
        query = if merged.is_empty() {
            None
        } else {
            Some(merged)
        };
    }

    if let Some(prefix) = &cfg.strip_prefix {
        if let Some(rest) = path.strip_prefix(prefix.as_str()) {
            path = if rest.is_empty() {
                "/".to_string()
            } else {
                rest.to_string()
            };
        }
    }

    (path, query)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn put_str(m: &mut Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        m.insert(key.to_string(), Value::from(value));
    }
}

enum ForwardAuthOutcome {
    Allow(Vec<(String, String)>),
    Deny(u16, Vec<u8>),
}

fn auth_client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build forward-auth client")
    })
}

/// Delegate authorization to an external service. On 2xx, returns the configured
/// response headers to copy upstream; otherwise returns the auth response to
/// relay to the client. A transport error denies with 401.
async fn forward_auth(session: &Session, fa: &ForwardAuth, host: &str) -> ForwardAuthOutcome {
    let (method, uri) = {
        let req = session.req_header();
        (
            req.method.to_string(),
            req.uri
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/")
                .to_string(),
        )
    };

    let mut builder = auth_client()
        .get(&fa.url)
        .header("X-Forwarded-Method", method)
        .header("X-Forwarded-Uri", uri)
        .header("X-Forwarded-Host", host);
    for h in &fa.auth_request_headers {
        if let Some(v) = header_str(session, h) {
            builder = builder.header(h, v);
        }
    }

    match builder.send().await {
        Ok(resp) if resp.status().is_success() => {
            let mut headers = Vec::new();
            for h in &fa.auth_response_headers {
                if let Some(v) = resp.headers().get(h).and_then(|v| v.to_str().ok()) {
                    headers.push((h.clone(), v.to_string()));
                }
            }
            ForwardAuthOutcome::Allow(headers)
        }
        Ok(resp) => {
            let code = resp.status().as_u16();
            let body = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
            ForwardAuthOutcome::Deny(code, body)
        }
        Err(_) => ForwardAuthOutcome::Deny(401, b"Unauthorized".to_vec()),
    }
}

async fn respond_with_body(session: &mut Session, code: u16, body: Vec<u8>) -> Result<()> {
    let mut resp = ResponseHeader::build(code, None)?;
    resp.insert_header("Content-Length", body.len().to_string())?;
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(bytes::Bytes::from(body)), true)
        .await
}

async fn respond_status(session: &mut Session, code: u16) -> Result<()> {
    let resp = ResponseHeader::build(code, None)?;
    session.write_response_header(Box::new(resp), true).await
}

async fn respond_redirect(session: &mut Session, code: u16, location: &str) -> Result<()> {
    let mut resp = ResponseHeader::build(code, None)?;
    resp.insert_header("Location", location)?;
    session.write_response_header(Box::new(resp), true).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ct_resp(ct: &str) -> ResponseHeader {
        let mut r = ResponseHeader::build(200, None).unwrap();
        r.insert_header("content-type", ct).unwrap();
        r
    }

    #[test]
    fn detects_event_stream_content_type() {
        assert!(is_event_stream(&ct_resp("text/event-stream")));
        assert!(is_event_stream(&ct_resp(
            "text/event-stream; charset=utf-8"
        )));
        assert!(is_event_stream(&ct_resp("Text/Event-Stream")));
        assert!(!is_event_stream(&ct_resp("text/html")));
        assert!(!is_event_stream(&ct_resp("application/json")));
        // missing content-type -> not SSE (stays compressible)
        assert!(!is_event_stream(&ResponseHeader::build(200, None).unwrap()));
    }

    #[test]
    fn trust_proxy_expands_shorthands_and_cidrs() {
        let tp = TrustProxy::parse("cloudflare,10.0.0.0/8");
        // 173.245.48.0/20 is a Cloudflare range
        assert!(tp.trusts("173.245.48.7".parse().unwrap()));
        assert!(tp.trusts("10.1.2.3".parse().unwrap()));
        assert!(!tp.trusts("8.8.8.8".parse().unwrap()));

        assert!(matches!(TrustProxy::parse("true"), TrustProxy::All));
        assert!(matches!(TrustProxy::parse(""), TrustProxy::None));
        assert!(matches!(TrustProxy::parse("false"), TrustProxy::None));
        // unknown token is ignored, not treated as a CIDR
        assert!(matches!(TrustProxy::parse("nonsense"), TrustProxy::Cidrs(v) if v.is_empty()));
    }

    use crate::config::UpstreamPath;

    #[test]
    fn rewrite_path_query_passthrough_when_no_annotations() {
        let cfg = RouteConfig::default();
        assert_eq!(
            rewrite_path_query("/api/x", Some("a=1"), &cfg),
            ("/api/x".to_string(), Some("a=1".to_string()))
        );
        assert_eq!(rewrite_path_query("/", None, &cfg), ("/".to_string(), None));
    }

    #[test]
    fn rewrite_path_query_strip_prefix() {
        let cfg = RouteConfig {
            strip_prefix: Some("/api".to_string()),
            ..Default::default()
        };
        assert_eq!(rewrite_path_query("/api/users", None, &cfg).0, "/users");
        assert_eq!(rewrite_path_query("/api", None, &cfg).0, "/"); // exact -> root
        assert_eq!(rewrite_path_query("/other", None, &cfg).0, "/other"); // no match
    }

    #[test]
    fn rewrite_path_query_upstream_path_merges_query() {
        let cfg = RouteConfig {
            upstream_path: Some(UpstreamPath {
                path: "/v2".to_string(),
                raw_query: "k=1".to_string(),
            }),
            ..Default::default()
        };
        let (p, q) = rewrite_path_query("/users", Some("a=2"), &cfg);
        assert_eq!(p, "/v2/users");
        assert_eq!(q.as_deref(), Some("k=1&a=2")); // upstream query first
        assert_eq!(
            rewrite_path_query("/users", None, &cfg).1.as_deref(),
            Some("k=1")
        );
    }

    #[test]
    fn rewrite_path_query_upstream_path_then_strip_prefix() {
        // upstream-path prepends, strip-prefix removes it again (order matters)
        let cfg = RouteConfig {
            upstream_path: Some(UpstreamPath {
                path: "/backend".to_string(),
                raw_query: String::new(),
            }),
            strip_prefix: Some("/backend".to_string()),
            ..Default::default()
        };
        assert_eq!(rewrite_path_query("/x", None, &cfg).0, "/x");
    }

    #[test]
    fn basic_auth_accepts_valid_and_rejects_everything_else() {
        let ba = BasicAuth {
            user: "admin".to_string(),
            pass: "s3cret".to_string(),
        };
        let enc = |s: &str| {
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(s)
            )
        };
        assert!(basic_auth_ok(Some(&enc("admin:s3cret")), &ba));
        assert!(!basic_auth_ok(Some(&enc("admin:wrong")), &ba)); // wrong pass
        assert!(!basic_auth_ok(Some(&enc("other:s3cret")), &ba)); // wrong user
        assert!(!basic_auth_ok(Some(&enc("noseparator")), &ba)); // no ':'
        assert!(!basic_auth_ok(None, &ba)); // missing header
        assert!(!basic_auth_ok(Some("Bearer xyz"), &ba)); // wrong scheme
        assert!(!basic_auth_ok(Some("Basic !!!notbase64"), &ba)); // bad base64
    }

    #[test]
    fn effective_protocol_resolution() {
        let mut ctx = Ctx {
            protocol: "h2c".to_string(),
            ..Default::default()
        };
        assert!(matches!(effective_protocol(&ctx), EffProto::H2c));
        ctx.protocol = "https".to_string();
        assert!(matches!(effective_protocol(&ctx), EffProto::Https));
        ctx.protocol = "http".to_string();
        assert!(matches!(effective_protocol(&ctx), EffProto::Http));
        // empty annotation falls back to the route's upstream-protocol
        ctx.protocol = String::new();
        ctx.config = Some(Arc::new(RouteConfig {
            upstream_protocol: UpstreamProtocol::Https,
            ..Default::default()
        }));
        assert!(matches!(effective_protocol(&ctx), EffProto::Https));
        ctx.config = Some(Arc::new(RouteConfig::default())); // default Http
        assert!(matches!(effective_protocol(&ctx), EffProto::Http));
    }

    #[test]
    fn ct_eq_is_correct() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(ct_eq(b"", b""));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab")); // different lengths
    }
}
