//! Build and run the Pingora server: two proxy services sharing one `Shared`
//! (plaintext+h2c and TLS+SNI, per the Phase-0 two-services lesson), plus the
//! Prometheus metrics endpoint.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pingora::apps::HttpServerOptions;
use pingora::listeners::tls::TlsSettings;
use pingora::proxy::http_proxy_service;
use pingora::server::configuration::ServerConf;
use pingora::server::{RunArgs, Server, ShutdownSignal, ShutdownSignalWatch};
use pingora::services::listening::Service;
use tokio::signal::unix::{signal, SignalKind};

use super::cert::SniResolver;
use super::{Limits, Proxy, TrustProxy};
use crate::shared::Shared;

/// Max requests served per downstream keepalive connection before it is closed,
/// so per-connection memory is reclaimed under sustained load.
const DOWNSTREAM_KEEPALIVE_REQUEST_LIMIT: u32 = 10_000;

pub struct ServeConfig {
    pub http_addr: String,
    pub https_addr: Option<String>,
    pub metrics_addr: String,
    pub trust: Arc<TrustProxy>,
    pub limits: Arc<Limits>,
    pub log_enabled: bool,
    pub debug: bool,
    /// On SIGTERM, mark not-ready then keep serving this long before draining,
    /// so the LB/endpoints deregister this pod first (WAIT_BEFORE_SHUTDOWN).
    pub wait_before_shutdown: Duration,
    /// Upstream keepalive pool size (`TR_MAX_IDLE_CONNS_PER_HOST`). NOTE: Pingora's
    /// pool is process-global, not per-host like Go's Transport.MaxIdleConnsPerHost,
    /// so this is a best-effort mapping. `None` keeps Pingora's default (128).
    pub upstream_keepalive_pool_size: Option<usize>,
}

/// Custom shutdown watcher: on SIGTERM, flip readiness to not-ready and keep
/// serving for `wait` before signaling pingora to drain. Mirrors the Go
/// controller's WAIT_BEFORE_SHUTDOWN. SIGINT = immediate, SIGQUIT = upgrade
/// (pingora's defaults).
struct DelayedShutdown {
    shared: Arc<Shared>,
    wait: Duration,
}

#[async_trait]
impl ShutdownSignalWatch for DelayedShutdown {
    async fn recv(&self) -> ShutdownSignal {
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
        let mut sigquit = signal(SignalKind::quit()).expect("SIGQUIT handler");

        tokio::select! {
            _ = sigint.recv() => return ShutdownSignal::FastShutdown,
            _ = sigquit.recv() => return ShutdownSignal::GracefulUpgrade,
            _ = sigterm.recv() => {}
        }

        // SIGTERM: deregister first (readiness -> 503), keep serving for `wait`
        // (covers endpoint/LB propagation), then drain.
        self.shared.set_not_ready();
        if !self.wait.is_zero() {
            eprintln!(
                "[shutdown] SIGTERM: marked not-ready, serving {:?} before draining",
                self.wait
            );
            tokio::select! {
                _ = tokio::time::sleep(self.wait) => {}
                _ = sigint.recv() => return ShutdownSignal::FastShutdown, // abort wait
            }
        }
        eprintln!("[shutdown] draining");
        ShutdownSignal::GracefulTerminate
    }
}

/// Build the services and run forever (blocks; pingora owns the runtime and
/// signal handling).
pub fn run(shared: Arc<Shared>, cfg: ServeConfig) {
    // pingora's graceful shutdown does an UNCONDITIONAL `thread::sleep(grace_period
    // .unwrap_or(EXIT_TIMEOUT=300s))` — that would hang ~5min after draining (k8s
    // SIGKILLs it). Set 0; in-flight requests still drain via the runtime's
    // graceful_shutdown_timeout. The pre-drain delay is our WAIT_BEFORE_SHUTDOWN.
    let mut conf = ServerConf {
        grace_period_seconds: Some(0),
        ..Default::default()
    };
    if let Some(n) = cfg.upstream_keepalive_pool_size {
        conf.upstream_keepalive_pool_size = n;
    }
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    // Pingora's default is 1 worker thread *per service*; run each proxy service
    // across all available cores (otherwise the proxy is single-threaded).
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // plaintext + h2c frontend
    let mut plain = http_proxy_service(
        &server.configuration,
        Proxy::new(
            shared.clone(),
            false,
            cfg.trust.clone(),
            cfg.limits.clone(),
            cfg.log_enabled,
            cfg.debug,
        ),
    );
    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    // Cap requests per downstream keepalive connection so per-connection memory is
    // periodically reclaimed (nginx keepalive_requests analog; Pingora defaults to
    // unlimited). Generous so it never throttles legitimate keepalive throughput.
    opts.keepalive_request_limit = Some(DOWNSTREAM_KEEPALIVE_REQUEST_LIMIT);
    plain.app_logic_mut().unwrap().server_options = Some(opts);
    plain.threads = Some(threads);
    plain.add_tcp(&cfg.http_addr);
    server.add_service(plain);

    // TLS frontend with dynamic SNI cert selection
    if let Some(https_addr) = cfg.https_addr {
        let mut tls_svc = http_proxy_service(
            &server.configuration,
            Proxy::new(
                shared.clone(),
                true,
                cfg.trust.clone(),
                cfg.limits.clone(),
                cfg.log_enabled,
                cfg.debug,
            ),
        );
        let resolver = SniResolver::new(shared.clone());
        let mut tls = TlsSettings::with_callbacks(Box::new(resolver)).expect("tls settings");
        tls.enable_h2();
        let mut tls_opts = HttpServerOptions::default();
        tls_opts.keepalive_request_limit = Some(DOWNSTREAM_KEEPALIVE_REQUEST_LIMIT);
        tls_svc.app_logic_mut().unwrap().server_options = Some(tls_opts);
        tls_svc.threads = Some(threads);
        tls_svc.add_tls_with_settings(&https_addr, None, tls);
        server.add_service(tls_svc);
    }

    // Prometheus endpoint (serves the process-default registry our metrics use)
    let mut prom = Service::prometheus_http_service();
    prom.add_tcp(&cfg.metrics_addr);
    server.add_service(prom);

    // Run with the WAIT_BEFORE_SHUTDOWN-aware shutdown watcher (replaces
    // run_forever's default signal handling).
    let shutdown = DelayedShutdown {
        shared,
        wait: cfg.wait_before_shutdown,
    };
    server.run(RunArgs {
        shutdown_signal: Box::new(shutdown),
    });
    std::process::exit(0);
}
