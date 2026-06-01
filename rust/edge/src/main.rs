//! parapet edge — out-of-cluster Pingora proxy that terminates public TLS locally
//! (cert+key fetched from the in-cluster control plane and cached in memory) and
//! forwards to parapet. See ../../EDGE.md. Phase 1: cert distribution + TLS +
//! forwarding. Phases 2–3 add edge WAF.

mod certstore;
mod cp;
mod diskcache;
mod proxy;
mod refresh;
mod tls;
mod waf;
mod wafrefresh;

// jemalloc as the global allocator — same reasoning as the controller (see
// controller/src/main.rs): glibc keeps freed memory in per-thread arenas and
// seldom returns it to the OS, so under Pingora's many-worker-thread HTTP/2 load
// resident memory ratchets upward for the process lifetime. jemalloc fragments
// far less and purges idle pages back to the OS on a decay timer (defaults:
// dirty_decay_ms=10s, muzzy_decay_ms=0). `background_threads` runs that purge
// off the request path on Linux; `unprefixed_malloc_on_supported_platforms`
// routes the C deps (OpenSSL) through jemalloc too. Override decay at runtime
// with `_RJEM_MALLOC_CONF`. msvc isn't a build target.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::sync::Arc;
use std::time::Duration;

use pingora::cache::eviction::lru::Manager as LruManager;
use pingora::cache::eviction::EvictionManager;
use pingora::cache::lock::{CacheKeyLockImpl, CacheLock};
use pingora::listeners::tls::TlsSettings;
use pingora::proxy::http_proxy_service;
use pingora::server::Server;

use crate::certstore::CertStore;
use crate::cp::CpClient;
use crate::proxy::EdgeProxy;
use crate::tls::EdgeTls;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Open the GeoIP + ASN databases the same way the controller does: env path
/// (`""` disables), else the baked default; a missing default is a quiet no-op,
/// a missing explicit path is logged. Loading is always non-fatal.
fn load_geo_dbs() -> (
    Option<controller::waf::GeoIp>,
    Option<controller::waf::AsnDb>,
) {
    fn path_of(env: &str, default: &str) -> (String, bool) {
        match std::env::var(env) {
            Ok(v) => (v, true),
            Err(_) => (default.to_string(), false),
        }
    }
    let (gp, g_explicit) = path_of("WAF_GEOIP_DB", "/geoip/ip-to-country.mmdb");
    let geoip = if gp.is_empty() {
        None
    } else {
        match controller::waf::GeoIp::open(&gp) {
            Ok(g) => {
                tracing::info!(path = %gp, "edge: geoip database loaded");
                Some(g)
            }
            Err(e) => {
                if g_explicit {
                    tracing::warn!(error = %e, "edge: geoip load failed; request.country will be empty");
                }
                None
            }
        }
    };
    let (ap, a_explicit) = path_of("WAF_ASN_DB", "/geoip/ip-to-asn.mmdb");
    let asndb = if ap.is_empty() {
        None
    } else {
        match controller::waf::AsnDb::open(&ap) {
            Ok(a) => {
                tracing::info!(path = %ap, "edge: asn database loaded");
                Some(a)
            }
            Err(e) => {
                if a_explicit {
                    tracing::warn!(error = %e, "edge: asn load failed; request.asn will be 0");
                }
                None
            }
        }
    };
    (geoip, asndb)
}

/// Build the edge response cache from env (`EDGE_CACHE_*`), or `None` when
/// disabled. Leaks the disk storage / LRU eviction manager / cache lock to
/// `'static` (Pingora's cache APIs take `&'static`), then re-seeds the eviction
/// manager from whatever survived on disk so the byte cap holds across restarts
/// (its accounting is otherwise in-memory only). See diskcache.rs + EDGE.md.
fn build_cache() -> Option<proxy::EdgeCache> {
    if env_or("EDGE_CACHE_ENABLED", "false") != "true" {
        return None;
    }
    let dir = env_or("EDGE_CACHE_DIR", "/var/cache/parapet-edge");
    let max_size: usize = env_or("EDGE_CACHE_MAX_SIZE", "1073741824")
        .parse()
        .unwrap_or(1 << 30);
    let max_file: usize = env_or("EDGE_CACHE_MAX_FILE_SIZE", "8388608")
        .parse()
        .unwrap_or(8 << 20);

    let dc = match diskcache::DiskCache::new(&dir, max_file) {
        Ok(dc) => dc,
        Err(e) => {
            tracing::error!(error = %e, dir, "edge cache: cannot init cache dir; caching disabled");
            return None;
        }
    };
    let storage: &'static diskcache::DiskCache = Box::leak(Box::new(dc));
    let eviction: &'static LruManager<8> =
        Box::leak(Box::new(LruManager::<8>::with_capacity(max_size, 1024)));

    // Re-admit surviving entries (orphans/torn writes are reaped by scan()).
    // admit() can return victims if we're already over the cap (e.g. the cap was
    // lowered since last run) — delete those files synchronously.
    let mut seeded = 0usize;
    let mut evicted = 0usize;
    for e in storage.scan() {
        for v in eviction.admit(e.key, e.size, e.fresh_until) {
            if storage.remove_blocking(&v) {
                evicted += 1;
            }
        }
        seeded += 1;
    }
    tracing::info!(
        dir,
        max_size,
        max_file,
        seeded,
        evicted,
        "edge cache enabled (disk-backed)"
    );

    // The cache lock collapses concurrent misses for one key into a single origin
    // fetch; the timeout bounds how long a waiting reader blocks on the writer.
    let lock: &'static CacheKeyLockImpl = Box::leak(CacheLock::new_boxed(Duration::from_secs(2)));
    Some(proxy::EdgeCache {
        storage,
        eviction: eviction as &'static (dyn EvictionManager + Sync),
        lock,
        max_file_size: max_file,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let https_listen = env_or("EDGE_HTTPS_LISTEN", "0.0.0.0:443");
    let cp_endpoint = env_or("EDGE_CP_ENDPOINT", "https://controlplane:8443");
    let cp_token = std::env::var("EDGE_CP_TOKEN").map_err(|_| "EDGE_CP_TOKEN is required")?;
    let cp_ca = std::env::var("EDGE_CP_CA")
        .ok()
        .and_then(|p| std::fs::read(p).ok());
    let parapet_addr = env_or("EDGE_PARAPET_ADDR", "parapet:80");
    let parapet_tls = env_or("EDGE_PARAPET_TLS", "false") == "true";
    let parapet_sni = env_or("EDGE_PARAPET_SNI", "");
    let refresh_secs: u64 = env_or("EDGE_REFRESH_INTERVAL", "300")
        .parse()
        .unwrap_or(300);
    let waf_enabled = env_or("EDGE_WAF_ENABLED", "false") == "true";
    // EDGE_DOMAINS is the set of SNIs to pre-fetch (its shard). Empty = serve ALL
    // domains: certs are fetched on demand at handshake time (the CP's per-token
    // authz still decides which SNIs resolve).
    let domains: Vec<String> = env_or("EDGE_DOMAINS", "")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let serve_all = domains.is_empty();

    let cp = CpClient::new(cp_endpoint, cp_token, cp_ca)?;
    let store = Arc::new(CertStore::new());

    // A dedicated runtime owns the control-plane HTTP client. We block on the
    // initial fetch so certs are present before we accept connections, then keep
    // the runtime alive to drive the periodic refresh.
    let cp_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    if serve_all {
        tracing::info!("edge: EDGE_DOMAINS empty — serving ALL domains (certs fetched on demand)");
    } else {
        let loaded = cp_rt.block_on(refresh::refresh_all(&cp, &store, &domains));
        tracing::info!(loaded, total = domains.len(), "edge: initial cert load");
    }
    cp_rt.spawn(refresh::run(
        cp.clone(),
        store.clone(),
        domains,
        Duration::from_secs(refresh_secs),
    ));

    // Phase 2: optional global WAF as an early-drop layer (parapet stays
    // authoritative). Fetch the ruleset once before serving, then refresh on the
    // same interval; a fetch/compile failure is fail-static (keeps last-good).
    let waf = if waf_enabled {
        // GeoIP/ASN: the edge is the first hop, so it resolves request.country /
        // request.asn from the TRUE client IP. Same env contract as the
        // controller (WAF_GEOIP_DB / WAF_ASN_DB; "" disables; baked default path;
        // a missing default is a quiet no-op, a missing explicit path is logged).
        let (geoip, asndb) = load_geo_dbs();
        let w = Arc::new(waf::EdgeWaf::with_geo(geoip, asndb));
        let has_rules = cp_rt.block_on(wafrefresh::refresh_initial(&cp, &w));
        tracing::info!(has_rules, "edge: initial WAF ruleset load");
        cp_rt.spawn(wafrefresh::run(
            cp.clone(),
            w.clone(),
            Duration::from_secs(refresh_secs),
        ));
        Some(w)
    } else {
        None
    };

    // Optional disk-backed response cache (off by default; honor-origin policy,
    // bounded by EDGE_CACHE_MAX_SIZE). See build_cache + diskcache.rs.
    let cache = build_cache();

    let mut server = Server::new(None).map_err(|e| format!("server init: {e}"))?;
    server.bootstrap();

    let proxy = EdgeProxy {
        parapet_addr,
        parapet_tls,
        parapet_sni,
        waf,
        cache,
    };
    let mut svc = http_proxy_service(&server.configuration, proxy);

    // Serve-all mode fetches a missing SNI's cert on demand via the CP runtime.
    let edge_tls = if serve_all {
        EdgeTls::with_ondemand(store, cp.clone(), cp_rt.handle().clone())
    } else {
        EdgeTls::new(store)
    };
    let mut tls = TlsSettings::with_callbacks(Box::new(edge_tls))
        .map_err(|e| format!("tls settings: {e}"))?;
    tls.set_min_proto_version(Some(pingora::tls::ssl::SslVersion::TLS1_2))
        .map_err(|e| format!("min tls version: {e}"))?;
    tls.enable_h2();
    svc.add_tls_with_settings(&https_listen, None, tls);

    // Plaintext HTTP listener (default 0.0.0.0:80; set EDGE_HTTP_LISTEN="" to
    // disable). The edge does NOT redirect http→https; it forwards plain-HTTP
    // requests to parapet with `X-Forwarded-Proto: http` (set in
    // upstream_request_filter) so the core's per-ingress `redirect-https` plugin
    // makes that decision. The global/zone WAF runs on this listener too.
    let http_listen = env_or("EDGE_HTTP_LISTEN", "0.0.0.0:80");
    if !http_listen.is_empty() {
        svc.add_tcp(&http_listen);
        tracing::info!(%http_listen, "parapet edge HTTP listener (plaintext; no redirect, forwards to core)");
    }

    server.add_service(svc);
    tracing::info!(%https_listen, "parapet edge listening (local TLS termination)");
    let _cp_rt = cp_rt; // keep the refresh runtime alive
    server.run_forever()
}
