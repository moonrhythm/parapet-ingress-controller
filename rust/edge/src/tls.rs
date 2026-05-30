//! TLS accept callback: install the per-SNI cert+key from the in-memory store on
//! the in-flight handshake, falling back to a self-signed cert for unknown SNI.
//! Mirrors `controller::proxy::cert::SniResolver`, but the certs come from the
//! control-plane fetch (the store) rather than k8s Secrets, and the key is local
//! (not keyless). The handshake path is fully local — no control-plane call.

use std::sync::Arc;

use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;

use crate::certstore::CertStore;

pub struct EdgeTls {
    store: Arc<CertStore>,
    fallback_cert: X509,
    fallback_key: PKey<Private>,
}

impl EdgeTls {
    pub fn new(store: Arc<CertStore>) -> Self {
        let (fallback_cert, fallback_key) = generate_fallback();
        Self {
            store,
            fallback_cert,
            fallback_key,
        }
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
            if let Some(loaded) = self.store.get(&sni) {
                if let Some(p) = loaded.parsed() {
                    // Install leaf + every intermediate (clients that don't chase
                    // AIA need the full chain), then the local private key.
                    let _ = ext::ssl_use_certificate(ssl, &p.chain[0]);
                    for intermediate in &p.chain[1..] {
                        let _ = ext::ssl_add_chain_cert(ssl, intermediate);
                    }
                    let _ = ext::ssl_use_private_key(ssl, &p.key);
                    return;
                }
            }
        }

        // Unknown SNI / unparseable cert: serve the self-signed fallback so the
        // handshake completes deterministically (client sees "unknown authority").
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
