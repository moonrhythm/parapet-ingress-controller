//! The Pingora `ProxyHttp` implementation: routing, upstream selection
//! (http/https/h2c) with retry + bad-addr skip, per-route middleware, trust-proxy
//! / X-Forwarded-* handling, the JSON access log, and request metrics. Mirrors
//! the Go controller's request path.

pub mod allocmetrics;
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
use pingora::{Error, ErrorSource, ErrorType, Result};
use serde::Serialize;

use self::limit::{Guard, HostConcurrency};
use crate::config::{
    resolve_zone_key, single_joining_slash, BasicAuth, ForwardAuth, Hsts, RouteConfig,
};
use crate::reconcile::{RouteKind, RouteMeta, UpstreamScheme};
use crate::router::Match;
use crate::shared::Shared;
use crate::waf::Decision as WafDecision;

const MAX_RETRY: usize = 5;
const ACME_PREFIX: &str = "/.well-known/acme-challenge";
/// Default TCP connect timeout to an upstream pod (connect phase only).
/// Sized for same-zone, intra-cluster pods (single-digit-ms connects), bounding
/// worst-case `MAX_RETRY × timeout` pileup under load. Override per deployment
/// with `UPSTREAM_CONNECT_TIMEOUT`.
const DEFAULT_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Default connect + TLS-handshake timeout (connect phase only). Override with
/// `UPSTREAM_TOTAL_CONNECT_TIMEOUT`.
const DEFAULT_UPSTREAM_TOTAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Metric label substituted for a Host the router doesn't serve, so a flood of
/// random `Host` headers can't create unbounded Prometheus series (OOM vector).
const UNKNOWN_HOST_LABEL: &str = "other";

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

/// Upstream connect-phase timeouts (see the `DEFAULT_UPSTREAM_*` consts). Applied
/// to every `HttpPeer`; cover connect + TLS handshake only, never data transfer.
#[derive(Clone, Copy)]
pub struct UpstreamTimeouts {
    pub connect: Duration,
    pub total_connect: Duration,
}

impl Default for UpstreamTimeouts {
    fn default() -> Self {
        Self {
            connect: DEFAULT_UPSTREAM_CONNECT_TIMEOUT,
            total_connect: DEFAULT_UPSTREAM_TOTAL_CONNECT_TIMEOUT,
        }
    }
}

pub struct Proxy {
    shared: Arc<Shared>,
    is_tls: bool,
    trust: Arc<TrustProxy>,
    limits: Arc<Limits>,
    timeouts: UpstreamTimeouts,
    log_enabled: bool,
    /// When set (DEBUG_ENDPOINTS=true), serves GET /debug/routes.
    debug: bool,
    /// WAF master switch (WAF_ENABLED). When false the proxy does no WAF work.
    waf_enabled: bool,
}

impl Proxy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shared: Arc<Shared>,
        is_tls: bool,
        trust: Arc<TrustProxy>,
        limits: Arc<Limits>,
        timeouts: UpstreamTimeouts,
        log_enabled: bool,
        debug: bool,
        waf_enabled: bool,
    ) -> Self {
        Self {
            shared,
            is_tls,
            trust,
            limits,
            timeouts,
            log_enabled,
            debug,
            waf_enabled,
        }
    }

    /// Build the `request.*` data the WAF exposes to CEL, from the live session.
    /// Mirrors the Go `buildRequestMap`: `query` is the raw query string, `args`
    /// are decoded first-values, headers are lowercased, body is empty (header
    /// phase only — see `waf.rs` divergences).
    fn build_waf_request(
        &self,
        session: &Session,
        host: &str,
        method: &str,
        ctx: &Ctx,
    ) -> crate::waf::RequestData {
        use std::collections::HashMap;
        let req = session.req_header();
        let path = req.uri.path().to_string();
        let query = req.uri.query().unwrap_or("").to_string();
        let uri = req
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| path.clone());
        let proto = format!("{:?}", req.version);
        let scheme = if self.is_https(session) {
            "https"
        } else {
            "http"
        }
        .to_string();
        // X-Real-Ip was set by apply_forwarded_headers per the trust policy,
        // matching Go's clientIP preference (X-Real-IP first).
        let remote_ip = header_str(session, "x-real-ip")
            .unwrap_or_default()
            .to_string();
        // GeoIP: reuse the single per-request lookup done in `request_filter`
        // (cached on Ctx) instead of resolving the client IP again. `country` is
        // "" when GeoIP is off, "XX" when the DB can't place the IP; `asn` is 0
        // when off or unplaceable — exactly the `country_of` / `asn_of` mapping.
        let country = ctx.geo_country.clone().unwrap_or_default();
        let asn = ctx.geo_asn.unwrap_or(0);
        let content_length = content_length(session).map(|c| c as i64).unwrap_or(-1);

        let mut headers = HashMap::new();
        for (name, value) in req.headers.iter() {
            if let Ok(v) = value.to_str() {
                // first value wins, lowercase keys (HeaderMap iterates in order)
                headers
                    .entry(name.as_str().to_ascii_lowercase())
                    .or_insert_with(|| v.to_string());
            }
        }

        crate::waf::RequestData {
            method: method.to_string(),
            host: host.to_string(),
            path,
            query: query.clone(),
            uri,
            proto,
            scheme,
            remote_ip,
            country,
            asn,
            content_length,
            headers,
            cookies: parse_cookies(header_str(session, "cookie").unwrap_or("")),
            args: parse_query_args(&query),
            user_agent: header_str(session, "user-agent")
                .unwrap_or_default()
                .to_string(),
            referer: header_str(session, "referer")
                .unwrap_or_default()
                .to_string(),
            body: String::new(),
        }
    }
}

#[derive(Default)]
pub struct Ctx {
    // routing / upstream
    target: Option<String>,
    scheme: UpstreamScheme,
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
    /// `host` if the router serves it, else the [`UNKNOWN_HOST_LABEL`] sentinel.
    /// Used for every host-labeled Prometheus series so a random-Host flood can't
    /// grow cardinality without bound. The raw `host` is still used for the
    /// access log and proxy-error log.
    metric_host: String,
    request_url: String,
    request_body_size: i64,
    referer: String,
    user_agent: String,
    remote_ip: String,
    real_ip: String,
    forwarded_for: String,
    // GeoIP resolved once per request from the (trust-handled) client IP, then
    // shared by X-Forwarded-Country/ASN header injection and every WAF eval so
    // the IP is looked up once, not per consumer. `Some` mirrors the
    // `forwarded_country`/`forwarded_asn` "DB loaded" gating (`None` => DB off,
    // header left untouched); WAF reads them as `unwrap_or_default()`/`(0)`.
    geo_country: Option<String>,
    geo_asn: Option<i64>,
    meta: RouteMeta,
    pattern: String,
    skip_log: bool,
    // host concurrency — host + country slots acquired in `request_filter`.
    // Cleared in `response_filter` (i.e. when upstream response headers arrive),
    // matching Go's `ReleaseOnWriteHeader` + `ReleaseOnHijacked` so that
    // long-lived streaming responses (SSE `text/event-stream`, WebSocket-style
    // 101 upgrades) don't hold a slot for the entire stream lifetime. Any
    // guards still alive at end-of-request release on `Ctx` drop.
    limit_guards: Vec<Guard>,
    host_active: Option<(String, &'static str)>,
    // forward-auth response headers to copy upstream
    auth_response_headers: Vec<(String, String)>,
    // WAF request data, built lazily on the first eval that runs (global or
    // zone) and reused by the other so the ~15 string allocs + header map +
    // query parse happen at most once per request. Stays `None` when no WAF
    // eval runs, preserving the no-rules short-circuit.
    waf_request: Option<crate::waf::RequestData>,
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
        // Reassemble HTTP/2 split Cookie crumbs into one header up front (RFC 7540
        // §8.1.2.5) — Pingora, unlike Go's h2 server, doesn't. Done here so BOTH
        // the WAF cookie eval (`build_waf_request`) and the upstream request
        // (cloned from this session) see a single correct Cookie. See SPEC.md.
        coalesce_cookies(session.req_header_mut());

        let scheme = if self.is_tls { "https" } else { "http" };
        let remote_ip = client_ip(session);

        // trust-proxy / X-Forwarded-* (parapet proxy middleware)
        self.apply_forwarded_headers(session, remote_ip, scheme);

        // GeoIP: resolve the client IP (x-real-ip after trust handling) exactly
        // once per request, then reuse the result for both X-Forwarded-* header
        // injection and every WAF eval (see `build_waf_request`). Each `Some`
        // means the corresponding DB is loaded — the ISO code / AS number, or
        // "XX" / 0 for an unplaceable IP; `None` means the DB is off.
        let geo_ip = header_str(session, "x-real-ip").and_then(|s| s.parse::<IpAddr>().ok());
        ctx.geo_country = self.shared.waf.forwarded_country(geo_ip);
        ctx.geo_asn = self.shared.waf.forwarded_asn(geo_ip);

        // X-Forwarded-Country / X-Forwarded-ASN: hand the upstream the GeoIP
        // result. Each header is set only when its DB is loaded, overwriting any
        // client-supplied value so it can't be spoofed.
        if let Some(cc) = &ctx.geo_country {
            let _ = session
                .req_header_mut()
                .insert_header("x-forwarded-country", cc.clone());
        }
        if let Some(asn) = ctx.geo_asn {
            let _ = session
                .req_header_mut()
                .insert_header("x-forwarded-asn", asn.to_string());
        }

        let host = req_host(session);
        let path = session.req_header().uri.path().to_string();

        // Always-needed fields: request start (metrics duration), method (metrics
        // label), and host (the proxy-error log). The richer access-log fields are
        // captured only when the access log is enabled — with DISABLE_LOG=true none
        // of the timestamp / client-IP / URL / header-string work below is done per
        // request, so disabling the log actually removes its per-request cost.
        ctx.start = Some(Instant::now());
        ctx.method = session.req_header().method.to_string();
        ctx.host = host.clone();
        // Sanitize the Host for metric labels: a Host the router doesn't serve
        // (e.g. a random-Host flood, scanners) collapses to one sentinel series
        // instead of creating an unbounded number of them.
        ctx.metric_host = if self.shared.is_known_host(&host) {
            host.clone()
        } else {
            UNKNOWN_HOST_LABEL.to_string()
        };
        if self.log_enabled {
            ctx.timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
            ctx.remote_ip = remote_ip.map(|i| i.to_string()).unwrap_or_default();
            ctx.capture(session, scheme);
        }

        // health checks (run before logging, like the Go middleware order).
        // Only intercept when the request is addressed to an IP — k8s probes hit
        // the pod IP, never a configured domain. A request with a domain Host
        // falls through to normal routing, so `/healthz` on a real host reaches
        // its backend and external callers can't probe the controller's health.
        // Mirrors parapet's healthz `Host: false` semantics (net.ParseIP gate).
        if path == "/healthz" && is_ip_host(&host) {
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
        // Sanitize the Upgrade header to a bounded label (it's client-controlled,
        // so a raw label is an unbounded-cardinality / OOM vector — same class as
        // the host label). `known_upgrade` returns a `'static` label, so inc/dec
        // share it with no per-request allocation.
        let upgrade = metrics::known_upgrade(header_str(session, "upgrade").unwrap_or("").trim());
        metrics::host_active_inc(&ctx.metric_host, upgrade);
        ctx.host_active = Some((ctx.metric_host.clone(), upgrade));

        // Concurrency-limit keys use the sanitized host (see `metric_host`): for a
        // known host this is the host itself (unchanged behavior); unknown hosts
        // all share one bucket, which both caps the limiter's internal map and
        // lets the bucket shed a random-Host flood instead of growing per-host.
        if let Some(country_limit) = &self.limits.country {
            let country = self
                .limits
                .country_headers
                .iter()
                .find_map(|h| header_str(session, h))
                .filter(|s| !s.is_empty())
                .unwrap_or("XX");
            let key = format!("{}|{country}", ctx.metric_host);
            match country_limit.acquire(&key).await {
                Some(g) => ctx.limit_guards.push(g),
                None => return self.reject_overloaded(session, ctx).await,
            }
        }
        if let Some(host_limit) = &self.limits.host {
            let key = ctx.metric_host.clone();
            match host_limit.acquire(&key).await {
                Some(g) => ctx.limit_guards.push(g),
                None => return self.reject_overloaded(session, ctx).await,
            }
        }

        // Global WAF (always-on baseline) runs before routing. An authoritative
        // platform block here can't be overridden by a tenant zone. Skipped when
        // disabled or no global rules are loaded (no per-request map built).
        if self.waf_enabled && self.shared.waf.global_has_rules() {
            let built = self.build_waf_request(session, &host, &ctx.method, ctx);
            let req = ctx.waf_request.insert(built);
            let decision = self.shared.waf.evaluate_global(req, |id, action| {
                metrics::waf_match_inc(id, action.as_str(), "global")
            });
            if let WafDecision::Block { status, message } = decision {
                metrics::rejected_inc("waf");
                respond_with_body(session, status, message.into_bytes()).await?;
                return Ok(true);
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
                    RouteKind::Service { target, scheme } => {
                        ctx.target = Some(target.clone());
                        ctx.scheme = *scheme;
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
                metrics::rejected_inc("no_route");
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

        let Some(addr) = self.shared.route_table.lookup(target) else {
            return Err(Error::explain(
                ErrorType::HTTPStatus(503),
                "service unavailable",
            ));
        };
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

        let mut peer = match ctx.scheme {
            UpstreamScheme::H2c => {
                let mut p = HttpPeer::new(addr.as_str(), false, String::new());
                p.options.alpn = ALPN::H2;
                p
            }
            UpstreamScheme::Https => {
                let mut p = HttpPeer::new(addr.as_str(), true, String::new());
                p.options.alpn = ALPN::H2H1;
                p.options.verify_cert = false;
                p.options.verify_hostname = false;
                p
            }
            UpstreamScheme::Http => {
                let mut p = HttpPeer::new(addr.as_str(), false, String::new());
                p.options.alpn = ALPN::H1;
                p
            }
        };
        // Bound the connect phase. Pingora defaults these to None (unbounded), so
        // when a backend is overwhelmed — exactly what a DDoS does — each request
        // would otherwise block on connect for the OS default (minutes), piling up
        // in-flight until the proxy itself exhausts fds/memory. A bounded connect
        // fails fast into fail_to_connect -> mark_bad -> round-robin to a healthy
        // pod. These cover only the connect/TLS handshake, NOT data transfer, so
        // long-lived streams (SSE / websockets / long-poll) are unaffected.
        peer.options.connection_timeout = Some(self.timeouts.connect);
        peer.options.total_connection_timeout = Some(self.timeouts.total_connect);
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
        // Release host/country concurrency slots as soon as upstream response
        // headers arrive. Matches Go's `ReleaseOnWriteHeader` + `ReleaseOnHijacked`
        // (101 Switching Protocols hits this hook too): the cap exists to shed
        // load while upstreams are unresponsive, not to count long-lived streams
        // (SSE, WebSocket, long-poll) which would otherwise pin a slot for the
        // whole stream lifetime.
        ctx.limit_guards.clear();

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

    /// What Pingora prints for this request in its own error logs. The default
    /// (`Session::request_summary`) includes the full request target *with the
    /// query string*, which can carry sensitive data (tokens, emails, etc.). We
    /// keep the same `"{method} {path}, Host: {host}"` shape but drop the query.
    fn request_summary(&self, session: &Session, _ctx: &Ctx) -> String {
        redacted_summary(session.req_header(), &req_host(session))
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Ctx) {
        // always release the host-active + backend in-flight gauges
        if let Some((host, upgrade)) = &ctx.host_active {
            metrics::host_active_dec(host, upgrade);
        }
        if let Some(addr) = ctx.backend_conn_addr.take() {
            metrics::backend_conn_dec(&addr);
        }
        // Surface upstream/internal failures (otherwise only a bare 502 is
        // visible). Skip Downstream-source errors: those are client-caused — a
        // client disconnecting before the response body completes (e.g. a
        // notification/SSE/long-poll client closing its stream) is expected and
        // high-volume, not an actionable proxy error.
        if let Some(e) = e {
            if should_log_proxy_error(e) {
                eprintln!(
                    "[proxy-error] host={} target={:?} proto={:?} tries={} err={}",
                    ctx.host, ctx.last_addr, ctx.scheme, ctx.tries, e
                );
            }
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
            host: &ctx.metric_host,
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
            let log = AccessLog {
                duration: duration.as_nanos() as i64,
                duration_human: format!("{duration:?}"),
                forwarded_for: &ctx.forwarded_for,
                host: &ctx.host,
                ingress: &ctx.meta.ingress_name,
                namespace: &ctx.meta.ingress_namespace,
                real_ip: &ctx.real_ip,
                referer: &ctx.referer,
                remote_ip: &ctx.remote_ip,
                request_body_size: (ctx.request_body_size > 0).then_some(ctx.request_body_size),
                request_method: &ctx.method,
                request_url: &ctx.request_url,
                response_body_size: (body_sent > 0).then_some(body_sent),
                service_name: &ctx.meta.service_name,
                service_target: ctx.last_addr.as_deref(),
                service_type: &ctx.meta.service_type,
                status,
                timestamp: &ctx.timestamp,
                user_agent: &ctx.user_agent,
            };
            if let Ok(line) = serde_json::to_string(&log) {
                println!("{line}");
            }
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
                metrics::rejected_inc("forbidden");
                respond_status(session, 403).await?;
                return Ok(true);
            }
        }

        // Per-zone WAF (tenant rules), bound by the waf-zone annotation and
        // resolved live against the registry — so a zone edit or a newly-created
        // zone takes effect without a reconcile. Runs after the global WAF
        // (request_filter) and the IP allow-list, before the redirect/auth gates.
        if self.waf_enabled {
            if let Some(key) = cfg
                .waf_zone
                .as_deref()
                .and_then(|raw| resolve_zone_key(&ctx.meta.ingress_namespace, raw))
            {
                if let Some(zone) = self.shared.waf.zone(&key) {
                    // Reuse the request data the global eval already built; only
                    // build it here when the global WAF was disabled or had no
                    // rules (so it never ran and the cache is still empty).
                    if ctx.waf_request.is_none() {
                        let built = self.build_waf_request(session, host, &ctx.method, ctx);
                        ctx.waf_request = Some(built);
                    }
                    let req = ctx.waf_request.as_ref().unwrap();
                    let decision = self.shared.waf.evaluate_zone(&zone, req, |id, action| {
                        metrics::waf_match_inc(id, action.as_str(), "zone")
                    });
                    if let WafDecision::Block { status, message } = decision {
                        metrics::rejected_inc("waf");
                        respond_with_body(session, status, message.into_bytes()).await?;
                        return Ok(true);
                    }
                }
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
            metrics::rejected_inc("rate_limit");
            respond_status(session, 429).await?;
            return Ok(true);
        }

        if let Some(limit) = cfg.body_limit {
            if content_length(session).is_some_and(|cl| cl > limit as u64) {
                metrics::rejected_inc("body_limit");
                respond_status(session, 413).await?;
                return Ok(true);
            }
        }

        if let Some(ba) = &cfg.basic_auth {
            if !check_basic_auth(session, ba) {
                metrics::rejected_inc("unauthorized");
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
                    metrics::rejected_inc("unauthorized");
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

    async fn reject_overloaded(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        metrics::host_ratelimit_inc(&ctx.metric_host);
        metrics::rejected_inc("host_limit");
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
    /// Capture the access-log-only fields. Called only when the access log is
    /// enabled (see `request_filter`); `method` and `host` are set there because
    /// metrics and the proxy-error log need them even with the log disabled.
    fn capture(&mut self, session: &Session, scheme: &str) {
        let req = session.req_header();
        // Path only — never the query string, which can carry sensitive data
        // (tokens, emails). Same reason `request_summary` redacts pingora's error
        // logs; this keeps it out of the JSON access log's `requestUrl` too.
        let path = req.uri.path();
        self.request_url = format!("{scheme}://{}{path}", self.host);
        self.request_body_size = content_length(session).map(|c| c as i64).unwrap_or(-1);
        // Strip the Referer's query too — a client-supplied URL can leak secrets
        // there (e.g. an OAuth code in a redirect Referer).
        self.referer = strip_query(header_str(session, "referer").unwrap_or_default()).to_string();
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

/// Whether a proxy error is worth logging as `[proxy-error]`. Downstream-source
/// errors are client-caused — most commonly a client disconnecting before the
/// response body completes (a notification/SSE/long-poll client closing its
/// stream) — which is expected and high-volume, not an actionable proxy error.
/// Only upstream/internal failures are surfaced.
fn should_log_proxy_error(e: &Error) -> bool {
    !matches!(e.esource, ErrorSource::Downstream)
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

/// Reassemble HTTP/2 split `Cookie` header fields into a single `Cookie` line.
///
/// RFC 7540 §8.1.2.5: an HTTP/2 client may split `Cookie` into multiple header
/// fields for HPACK compression. A proxy forwarding the request MUST concatenate
/// them back into one `Cookie: a=1; b=2` (Go's `net/http` HTTP/2 server does this
/// before the request reaches proxy logic). Pingora does NOT, so without this a
/// split cookie reaches the backend as multiple `Cookie:` lines; frameworks that
/// read only the first crumb then lose the session cookie -> forced logout. This
/// is the Go↔Rust divergence behind the "Rust controller logs users out (Safari
/// worst, Chrome random), Go works" report. See SPEC.md.
fn coalesce_cookies(req: &mut RequestHeader) {
    // 0 or 1 Cookie field: forward verbatim (the common HTTP/1.1 case).
    if req.headers.get_all("cookie").iter().count() <= 1 {
        return;
    }
    // >1 field: the client split it. Rejoin the non-empty crumbs with "; " (the
    // cookie-pair separator) into a single header. `insert_header` replaces all
    // existing `cookie` fields with the one joined value.
    let joined = req
        .headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    let _ = req.insert_header("cookie", joined);
}

/// Parse a `Cookie` header into a name->value map (last write wins, matching Go's
/// `Request.Cookies` behavior). Values are not unquoted (a minor divergence).
fn parse_cookies(s: &str) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    for part in s.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            m.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    m
}

/// Parse a raw query string into a first-value-per-key map, percent-decoding keys
/// and values like Go's `url.Query()`. `request.query` stays raw; only `args` is
/// decoded (matching the Go controller).
fn parse_query_args(query: &str) -> std::collections::HashMap<String, String> {
    let decode = |s: &str| crate::waf::query_unescape(s).unwrap_or_else(|| s.to_string());
    let mut m = std::collections::HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        m.entry(decode(k)).or_insert_with(|| decode(v));
    }
    m
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

/// Whether `host` (already port-stripped by [`req_host`]) is an IP literal — the
/// gate for serving `/healthz`. A domain host is not, so it routes normally.
/// Empty likewise isn't an IP, matching parapet's `net.ParseIP` behavior.
fn is_ip_host(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
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

/// Build the request summary Pingora logs on error, without the query string.
/// `uri.path()` excludes the query, so secrets passed as query params never
/// reach the logs. Pure, so it's unit-testable.
fn redacted_summary(req: &RequestHeader, host: &str) -> String {
    format!("{} {}, Host: {host}", req.method.as_str(), req.uri.path())
}

/// Drop the `?query` (and anything after) from an arbitrary URL string, so a
/// query carrying sensitive data never reaches a log. Pure, unit-testable.
fn strip_query(s: &str) -> &str {
    s.split('?').next().unwrap_or(s)
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

/// One JSON access-log line, serialized once per request. Fields are declared
/// in the alphabetical key order the previous `serde_json::Map` (a `BTreeMap`)
/// emitted, so the log output stays byte-identical. Empty strings and unset
/// sizes/targets are omitted, matching the Go controller's access log.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessLog<'a> {
    duration: i64,
    duration_human: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    forwarded_for: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    host: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    ingress: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    namespace: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    real_ip: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    referer: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    remote_ip: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_body_size: Option<i64>,
    #[serde(skip_serializing_if = "str::is_empty")]
    request_method: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    request_url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_size: Option<i64>,
    #[serde(skip_serializing_if = "str::is_empty")]
    service_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_target: Option<&'a str>,
    #[serde(skip_serializing_if = "str::is_empty")]
    service_type: &'a str,
    status: u16,
    #[serde(skip_serializing_if = "str::is_empty")]
    timestamp: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    user_agent: &'a str,
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
    fn proxy_error_logging_skips_client_disconnects() {
        // Downstream (client-caused) errors — e.g. a client closing mid-response
        // — must NOT be logged as [proxy-error]; upstream/internal must be.
        let mut e = Error::explain(ErrorType::ConnectionClosed, "client closed");
        e.esource = ErrorSource::Downstream;
        assert!(!should_log_proxy_error(&e));
        e.esource = ErrorSource::Upstream;
        assert!(should_log_proxy_error(&e));
        e.esource = ErrorSource::Internal;
        assert!(should_log_proxy_error(&e));
    }

    #[test]
    fn is_ip_host_only_matches_ip_literals() {
        assert!(is_ip_host("127.0.0.1"), "IPv4 is an IP host");
        assert!(is_ip_host("10.0.0.5"));
        assert!(is_ip_host("::1"), "IPv6 is an IP host");
        assert!(!is_ip_host("api.example.com"), "domain is not");
        assert!(!is_ip_host(""), "empty is not");
        assert!(!is_ip_host("localhost"), "localhost is not an IP literal");
    }

    #[test]
    fn redacted_summary_drops_query_string() {
        let mut req =
            RequestHeader::build("GET", b"/pay?token=s3cret&email=a@b.com", None).unwrap();
        let _ = req.insert_header("host", "api.example.com");
        let summary = redacted_summary(&req, "api.example.com");
        assert_eq!(summary, "GET /pay, Host: api.example.com");
        assert!(!summary.contains("token"), "query string must not appear");
        assert!(!summary.contains("s3cret"));
        assert!(!summary.contains('?'));
    }

    // --- HTTP/2 split-Cookie reassembly (RFC 7540 §8.1.2.5) ----------------
    // Repro for the "Rust controller logs users out under HTTP/2 (Safari worst,
    // Chrome random); Go works" report. Browsers split Cookie into multiple
    // header fields over H2; the proxy must rejoin them before forwarding.

    fn cookie_values(req: &RequestHeader) -> Vec<String> {
        req.headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn coalesce_cookies_joins_split_h2_crumbs() {
        // Three crumbs as an H2 client would send them; must become ONE header
        // "a; b; c" (order preserved). A backend reading only the first crumb
        // otherwise loses `session` -> forced logout. FAILS before the fix.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.append_header("cookie", "session=abc").unwrap();
        req.append_header("cookie", "csrf=xyz").unwrap();
        req.append_header("cookie", "theme=dark").unwrap();

        coalesce_cookies(&mut req);

        assert_eq!(
            cookie_values(&req),
            vec!["session=abc; csrf=xyz; theme=dark"],
            "split H2 Cookie crumbs must be rejoined into one '; '-separated header"
        );
    }

    #[test]
    fn coalesce_cookies_leaves_single_cookie_unchanged() {
        // Guard: a single (already-joined) Cookie must pass through verbatim —
        // no trailing "; ", no duplication.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.append_header("cookie", "session=abc; csrf=xyz")
            .unwrap();

        coalesce_cookies(&mut req);

        assert_eq!(cookie_values(&req), vec!["session=abc; csrf=xyz"]);
    }

    #[test]
    fn coalesce_cookies_absent_stays_absent() {
        // Guard: never synthesize an empty Cookie header when there was none.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();

        coalesce_cookies(&mut req);

        assert!(
            req.headers.get("cookie").is_none(),
            "must not add a Cookie header when the request had none"
        );
    }

    #[test]
    fn strip_query_drops_query() {
        assert_eq!(
            strip_query("https://ref/page?token=s3cret"),
            "https://ref/page"
        );
        assert_eq!(strip_query("/just/a/path"), "/just/a/path");
        assert_eq!(strip_query(""), "");
    }

    #[test]
    fn ct_eq_is_correct() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(ct_eq(b"", b""));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab")); // different lengths
    }

    #[test]
    fn access_log_serializes_in_order_with_all_fields() {
        let log = AccessLog {
            duration: 1500,
            duration_human: "1.5µs".to_string(),
            forwarded_for: "1.2.3.4",
            host: "example.com",
            ingress: "ing",
            namespace: "default",
            real_ip: "1.2.3.4",
            referer: "https://ref/",
            remote_ip: "5.6.7.8",
            request_body_size: Some(10),
            request_method: "GET",
            request_url: "https://example.com/",
            response_body_size: Some(20),
            service_name: "web",
            service_target: Some("10.0.0.1:8080"),
            service_type: "ClusterIP",
            status: 200,
            timestamp: "2026-05-25T00:00:00Z",
            user_agent: "curl",
        };
        assert_eq!(
            serde_json::to_string(&log).unwrap(),
            r#"{"duration":1500,"durationHuman":"1.5µs","forwardedFor":"1.2.3.4","host":"example.com","ingress":"ing","namespace":"default","realIp":"1.2.3.4","referer":"https://ref/","remoteIp":"5.6.7.8","requestBodySize":10,"requestMethod":"GET","requestUrl":"https://example.com/","responseBodySize":20,"serviceName":"web","serviceTarget":"10.0.0.1:8080","serviceType":"ClusterIP","status":200,"timestamp":"2026-05-25T00:00:00Z","userAgent":"curl"}"#
        );
    }

    #[test]
    fn access_log_omits_empty_and_unset_fields() {
        // empty strings, unset sizes and target are dropped; duration/status stay
        let log = AccessLog {
            duration: 42,
            duration_human: "42ns".to_string(),
            forwarded_for: "",
            host: "",
            ingress: "",
            namespace: "",
            real_ip: "",
            referer: "",
            remote_ip: "",
            request_body_size: None,
            request_method: "",
            request_url: "",
            response_body_size: None,
            service_name: "",
            service_target: None,
            service_type: "",
            status: 404,
            timestamp: "",
            user_agent: "",
        };
        assert_eq!(
            serde_json::to_string(&log).unwrap(),
            r#"{"duration":42,"durationHuman":"42ns","status":404}"#
        );
    }
}
