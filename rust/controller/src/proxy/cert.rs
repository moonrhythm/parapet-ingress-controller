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

use super::metrics;
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

        // Classify the outcome so a fallback is never silent: a client that
        // receives the self-signed fallback sees "certificate signed by unknown
        // authority", with no server-side signal. `reason` distinguishes the
        // client connecting without SNI (or by IP) from a genuinely missing cert
        // from a cert that's loaded but unusable (e.g. missing/invalid tls.key).
        let reason = if sni.is_empty() {
            "no_sni"
        } else if let Some(loaded) = self.shared.certs.load().get(&sni) {
            match (
                X509::from_pem(&loaded.cert_pem),
                PKey::private_key_from_pem(&loaded.key_pem),
            ) {
                (Ok(cert), Ok(key)) => {
                    let _ = ext::ssl_use_certificate(ssl, &cert);
                    let _ = ext::ssl_use_private_key(ssl, &key);
                    return;
                }
                _ => "parse_error",
            }
        } else {
            "no_match"
        };

        metrics::tls_no_cert_inc(reason);
        // Throttled (the metric carries the true rate) so a TLS handshake flood
        // with random SNIs can't turn this into a log flood.
        if log_fallback_throttled() {
            eprintln!(
                "[tls] serving self-signed fallback: reason={reason} sni={sni:?} loaded_certs={}",
                self.shared.certs.load().names().len()
            );
        }
        let _ = ext::ssl_use_certificate(ssl, &self.fallback_cert);
        let _ = ext::ssl_use_private_key(ssl, &self.fallback_key);
    }
}

/// Allow the fallback log at most ~once per second, process-wide.
fn log_fallback_throttled() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let last = LAST.load(Ordering::Relaxed);
    now > last
        && LAST
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

fn generate_fallback() -> (X509, PKey<Private>) {
    let ck = rcgen::generate_simple_self_signed(vec!["parapet-ingress-controller".to_string()])
        .expect("generate self-signed fallback cert");
    let cert = X509::from_pem(ck.cert.pem().as_bytes()).expect("parse fallback cert");
    let key = PKey::private_key_from_pem(ck.key_pair.serialize_pem().as_bytes())
        .expect("parse fallback key");
    (cert, key)
}
