//! Dynamic SNI certificate selection for the TLS listener. Reads the
//! hot-swappable cert table in `Shared` (PEM, indexed by SAN) and installs the
//! matching leaf on the in-flight handshake, falling back to a generated
//! self-signed cert for unknown SNI. Mirrors the Phase-0 spike, wired to live
//! state. (Parsing PEM per handshake is a known Phase-5 optimization target.)

use std::sync::Arc;

use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;

use crate::shared::Shared;

pub struct SniResolver {
    shared: Arc<Shared>,
    fallback_cert: X509,
    fallback_key: PKey<Private>,
}

impl SniResolver {
    pub fn new(shared: Arc<Shared>) -> Self {
        let (fallback_cert, fallback_key) = generate_fallback();
        Self {
            shared,
            fallback_cert,
            fallback_key,
        }
    }
}

#[async_trait]
impl TlsAccept for SniResolver {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let sni = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or_default()
            .to_string();

        if let Some(loaded) = self.shared.certs.load().get(&sni) {
            if let (Ok(cert), Ok(key)) = (
                X509::from_pem(&loaded.cert_pem),
                PKey::private_key_from_pem(&loaded.key_pem),
            ) {
                let _ = ext::ssl_use_certificate(ssl, &cert);
                let _ = ext::ssl_use_private_key(ssl, &key);
                return;
            }
        }

        let _ = ext::ssl_use_certificate(ssl, &self.fallback_cert);
        let _ = ext::ssl_use_private_key(ssl, &self.fallback_key);
    }
}

fn generate_fallback() -> (X509, PKey<Private>) {
    let ck = rcgen::generate_simple_self_signed(vec!["parapet-ingress-controller".to_string()])
        .expect("generate self-signed fallback cert");
    let cert = X509::from_pem(ck.cert.pem().as_bytes()).expect("parse fallback cert");
    let key = PKey::private_key_from_pem(ck.key_pair.serialize_pem().as_bytes())
        .expect("parse fallback key");
    (cert, key)
}
