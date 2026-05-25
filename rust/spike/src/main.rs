// Phase-0 spike: a single pingora proxy exercising every "risky" capability of
// the migration in one place:
//   * h2c upstream            (h2c.test  -> cleartext-HTTP/2 backend)
//   * h1 upstream             (h1.test   -> HTTP/1.1 backend)
//   * retry + bad-addr skip   (flaky.test -> [dead, live]; first dial fails, retries onto live)
//   * hot route reload        (late.test appears ~1.5s in via ArcSwap swap, under a swap loop)
//   * h2c frontend            (plaintext listener accepts HTTP/2 prior-knowledge)
//   * dynamic SNI termination (TLS listener picks cert by SNI from a hot-swappable store)
//
// Listeners: 127.0.0.1:6190 (plaintext + h2c), 127.0.0.1:6443 (TLS w/ SNI).

mod certs;
mod routing;
mod upstreams;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::apps::HttpServerOptions;
use pingora::listeners::tls::TlsSettings;
use pingora::protocols::ALPN;
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorType, Result};

use certs::{gen_cert, CertStore, SniResolver};
use routing::{Backend, BadAddrs, Proto, RouteTable};

#[derive(Clone)]
struct Spike {
    routes: Arc<ArcSwap<RouteTable>>,
    bad: Arc<BadAddrs>,
}

#[derive(Default)]
struct Ctx {
    last_addr: Option<String>,
    tries: usize,
}

const MAX_RETRY: usize = 5;

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

#[async_trait]
impl ProxyHttp for Spike {
    type CTX = Ctx;
    fn new_ctx(&self) -> Ctx {
        Ctx::default()
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        let host = req_host(session);
        let table = self.routes.load();
        let backend = table
            .get(&host)
            .ok_or_else(|| Error::explain(ErrorType::HTTPStatus(503), "no route"))?;
        let addr = backend
            .pick(&self.bad)
            .ok_or_else(|| Error::explain(ErrorType::HTTPStatus(503), "all backends bad"))?;
        ctx.last_addr = Some(addr.clone());

        let tls = matches!(backend.proto, Proto::Https);
        let mut peer = HttpPeer::new(addr.as_str(), tls, host);
        match backend.proto {
            Proto::H1 => peer.options.alpn = ALPN::H1,
            Proto::H2c => peer.options.alpn = ALPN::H2, // cleartext HTTP/2 prior-knowledge
            Proto::Https => {
                peer.options.alpn = ALPN::H2H1;
                peer.options.verify_cert = false; // InsecureSkipVerify parity
                peer.options.verify_hostname = false;
            }
        }
        Ok(Box::new(peer))
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Ctx,
        mut e: Box<Error>,
    ) -> Box<Error> {
        if let Some(a) = &ctx.last_addr {
            self.bad.mark(a); // skip this pod on the retry
        }
        ctx.tries += 1;
        if ctx.tries < MAX_RETRY {
            e.set_retry(true); // pingora re-invokes upstream_peer -> RRLB picks the next IP
        }
        e
    }
}

fn build_table(with_late: bool) -> RouteTable {
    let mut t = RouteTable::new();
    t.insert(
        "h1.test".into(),
        Backend::new(vec!["127.0.0.1:7001".into()], Proto::H1),
    );
    t.insert(
        "h2c.test".into(),
        Backend::new(vec!["127.0.0.1:7002".into()], Proto::H2c),
    );
    // dead IP first, live IP second -> exercises retry + bad-addr skip
    t.insert(
        "flaky.test".into(),
        Backend::new(
            vec!["127.0.0.1:7999".into(), "127.0.0.1:7001".into()],
            Proto::H1,
        ),
    );
    t.insert(
        "ws.test".into(),
        Backend::new(vec!["127.0.0.1:7003".into()], Proto::H1),
    );
    if with_late {
        t.insert(
            "late.test".into(),
            Backend::new(vec!["127.0.0.1:7001".into()], Proto::H1),
        );
    }
    t
}

fn main() {
    // test upstreams (127.0.0.1:7999 is intentionally left unbound = dead backend)
    upstreams::spawn_h1("127.0.0.1:7001", "h1");
    upstreams::spawn_h2c("127.0.0.1:7002", "h2c");
    upstreams::spawn_ws("127.0.0.1:7003");

    // routing starts WITHOUT late.test; a background thread swaps it in to prove
    // zero-downtime hot reload, then keeps swapping to show stability under churn.
    let routes = Arc::new(ArcSwap::from_pointee(build_table(false)));
    let bad = Arc::new(BadAddrs::new());
    {
        let routes = routes.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1500));
            routes.store(Arc::new(build_table(true)));
            loop {
                std::thread::sleep(Duration::from_millis(200));
                routes.store(Arc::new(build_table(true)));
            }
        });
    }

    // dynamic SNI cert store: exact foo/bar, wildcard *.wild.test, plus fallback
    let mut exact = HashMap::new();
    exact.insert("foo.test".to_string(), gen_cert(&["foo.test"]));
    exact.insert("bar.test".to_string(), gen_cert(&["bar.test"]));
    let mut wildcard = HashMap::new();
    wildcard.insert("*.wild.test".to_string(), gen_cert(&["*.wild.test"]));
    let store = Arc::new(ArcSwap::from_pointee(CertStore {
        exact,
        wildcard,
        fallback: gen_cert(&["fallback.local"]),
    }));

    let app = Spike {
        routes: routes.clone(),
        bad: bad.clone(),
    };

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    // Two services share the same proxy logic, mirroring the Go code's two
    // parapet.Servers. h2c (cleartext HTTP/2) must live ONLY on the plaintext
    // service: TLS streams can't peek for the H2 preface, so a shared h2c flag
    // would force H2 onto every TLS connection. The TLS service uses ALPN instead.
    let mut plain = http_proxy_service(&server.configuration, app.clone());
    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    plain.app_logic_mut().unwrap().server_options = Some(opts);
    plain.add_tcp("127.0.0.1:6190");
    server.add_service(plain);

    let mut tls_svc = http_proxy_service(&server.configuration, app);
    let resolver = SniResolver { store };
    let mut tls = TlsSettings::with_callbacks(Box::new(resolver)).unwrap();
    tls.enable_h2(); // advertise h2+http/1.1 via ALPN on the TLS listener
    tls_svc.add_tls_with_settings("127.0.0.1:6443", None, tls);
    server.add_service(tls_svc);

    println!("spike listening: plaintext+h2c 127.0.0.1:6190, TLS+SNI 127.0.0.1:6443");
    server.run_forever();
}
