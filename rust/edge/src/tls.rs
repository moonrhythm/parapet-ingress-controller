//! TLS accept callback: install the per-SNI cert+key from the in-memory store on
//! the in-flight handshake, falling back to a self-signed cert for unknown SNI.
//! Mirrors `controller::proxy::cert::SniResolver`, but the certs come from the
//! control-plane fetch (the store) rather than k8s Secrets, and the key is local
//! (not keyless).
//!
//! Two modes:
//! - **Pinned domains** (`EDGE_DOMAINS` set): the store is pre-populated; a miss
//!   serves the self-signed fallback. The handshake path is fully local.
//! - **Serve-all** (`EDGE_DOMAINS` empty): a miss triggers an on-demand fetch of
//!   that SNI's cert from the control plane (run on the CP runtime; the handshake
//!   awaits it), cached for next time. The CP's per-token authz still decides
//!   which SNIs resolve — a disallowed/unknown SNI 403/404s → fallback. This adds
//!   one control-plane round trip to the *first* handshake for each new SNI.

use std::sync::Arc;

use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;
use tokio::runtime::Handle;

use crate::certstore::CertStore;
use crate::cp::CpClient;

/// On-demand fetch wiring (serve-all mode): the control-plane client and a handle
/// to the runtime that owns it, so the handshake can drive a fetch off-thread.
struct OnDemand {
    cp: CpClient,
    rt: Handle,
}

pub struct EdgeTls {
    store: Arc<CertStore>,
    ondemand: Option<OnDemand>,
    fallback_cert: X509,
    fallback_key: PKey<Private>,
}

impl EdgeTls {
    /// Pinned-domains mode: serve only what's already in the store.
    pub fn new(store: Arc<CertStore>) -> Self {
        Self::build(store, None)
    }

    /// Serve-all mode: fetch a missing SNI's cert on demand via `cp` (driven on
    /// `rt`, the control-plane runtime).
    pub fn with_ondemand(store: Arc<CertStore>, cp: CpClient, rt: Handle) -> Self {
        Self::build(store, Some(OnDemand { cp, rt }))
    }

    fn build(store: Arc<CertStore>, ondemand: Option<OnDemand>) -> Self {
        let (fallback_cert, fallback_key) = generate_fallback();
        Self {
            store,
            ondemand,
            fallback_cert,
            fallback_key,
        }
    }

    /// Install the cert+key for `sni` onto the handshake if the store has it.
    /// Returns true on success.
    fn install(&self, ssl: &mut SslRef, sni: &str) -> bool {
        let Some(loaded) = self.store.get(sni) else {
            return false;
        };
        let Some(p) = loaded.parsed() else {
            return false;
        };
        let _ = ext::ssl_use_certificate(ssl, &p.chain[0]);
        for intermediate in &p.chain[1..] {
            let _ = ext::ssl_add_chain_cert(ssl, intermediate);
        }
        let _ = ext::ssl_use_private_key(ssl, &p.key);
        true
    }
}

#[async_trait]
impl TlsAccept for EdgeTls {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let sni = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or_default()
            .to_string();

        if !sni.is_empty() {
            if self.install(ssl, &sni) {
                return;
            }
            // Serve-all: miss → fetch this SNI's cert from the control plane (on
            // its own runtime), then retry. Awaited via a oneshot so reqwest stays
            // on the CP runtime, not pingora's.
            if let Some(od) = &self.ondemand {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cp = od.cp.clone();
                let store = self.store.clone();
                let want = sni.clone();
                od.rt.spawn(async move {
                    crate::refresh::refresh_one(&cp, &store, &want).await;
                    let _ = tx.send(());
                });
                let _ = rx.await;
                if self.install(ssl, &sni) {
                    return;
                }
            }
        }

        // Unknown SNI / unparseable cert / disallowed by the CP: serve the
        // self-signed fallback so the handshake completes deterministically
        // (client sees "unknown authority").
        let _ = ext::ssl_use_certificate(ssl, &self.fallback_cert);
        let _ = ext::ssl_use_private_key(ssl, &self.fallback_key);
    }
}

fn generate_fallback() -> (X509, PKey<Private>) {
    let ck = rcgen::generate_simple_self_signed(vec!["parapet-edge".to_string()])
        .expect("generate self-signed fallback cert");
    let cert = X509::from_pem(ck.cert.pem().as_bytes()).expect("parse fallback cert");
    let key = PKey::private_key_from_pem(ck.key_pair.serialize_pem().as_bytes())
        .expect("parse fallback key");
    (cert, key)
}
