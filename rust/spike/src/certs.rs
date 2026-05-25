// Dynamic SNI cert store + resolver. Mirrors cert/table.go: exact match, then a
// single-label wildcard climb, then a self-signed fallback. The store sits behind
// an ArcSwap so reloads are lock-free, and the resolver is plugged into pingora's
// TLS handshake via the TlsAccept::certificate_callback hook.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;

pub struct Cert {
    pub cert: X509,
    pub key: PKey<Private>,
}

pub struct CertStore {
    pub exact: HashMap<String, Arc<Cert>>,
    pub wildcard: HashMap<String, Arc<Cert>>, // keyed "*.example.com"
    pub fallback: Arc<Cert>,
}

impl CertStore {
    pub fn lookup(&self, sni: &str) -> Arc<Cert> {
        let name = sni.to_ascii_lowercase();
        if let Some(c) = self.exact.get(&name) {
            return c.clone();
        }
        if let Some(i) = name.find('.') {
            let wc = format!("*{}", &name[i..]);
            if let Some(c) = self.wildcard.get(&wc) {
                return c.clone();
            }
        }
        self.fallback.clone()
    }
}

pub struct SniResolver {
    pub store: Arc<ArcSwap<CertStore>>,
}

#[async_trait]
impl TlsAccept for SniResolver {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let sni = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or_default()
            .to_string();
        let cert = self.store.load().lookup(&sni);
        // these set the leaf cert + key on the in-flight handshake
        let _ = ext::ssl_use_certificate(ssl, &cert.cert);
        let _ = ext::ssl_use_private_key(ssl, &cert.key);
    }
}

/// Generate a self-signed cert/key for the given SANs (spike harness only).
pub fn gen_cert(sans: &[&str]) -> Arc<Cert> {
    let names: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let ck = rcgen::generate_simple_self_signed(names).unwrap();
    let cert = X509::from_pem(ck.cert.pem().as_bytes()).unwrap();
    let key = PKey::private_key_from_pem(ck.key_pair.serialize_pem().as_bytes()).unwrap();
    Arc::new(Cert { cert, key })
}
