//! SNI certificate lookup. Port of `cert/table.go`: index certificates by SAN,
//! look up by exact name, then climb a single wildcard label
//! (`www.example.com` -> `*.example.com`).
//!
//! Generic over [`HasDnsNames`] so the same table serves both unit tests and
//! the real OpenSSL-backed certs wired up in Phase 2. The TLS-handshake
//! compatibility check (`SupportsCertificate` in Go) belongs to the handshake
//! and is layered on at integration; this core resolves *names* to certs.

use std::collections::HashMap;
use std::sync::Arc;

pub trait HasDnsNames {
    fn dns_names(&self) -> &[String];
}

/// A TLS certificate loaded from a Kubernetes secret. The SAN DNS names are
/// extracted (pure Rust, via x509-parser) to build the SNI index; the raw PEM
/// bytes are retained so the proxy layer (Phase 2) can hand them to the TLS
/// backend. Mirrors loading `tls.crt`/`tls.key` from a `kubernetes.io/tls`
/// secret in the Go controller.
pub struct LoadedCert {
    dns_names: Vec<String>,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

impl HasDnsNames for LoadedCert {
    fn dns_names(&self) -> &[String] {
        &self.dns_names
    }
}

impl LoadedCert {
    /// Parse a cert/key PEM pair. Returns `None` if the certificate can't be
    /// parsed (the Go controller likewise skips such secrets). Full key/cert
    /// pairing validation is deferred to the TLS backend in Phase 2.
    pub fn from_pem(cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Option<Self> {
        let dns_names = extract_dns_names(&cert_pem)?;
        Some(Self {
            dns_names,
            cert_pem,
            key_pem,
        })
    }
}

fn extract_dns_names(cert_pem: &[u8]) -> Option<Vec<String>> {
    use x509_parser::extensions::GeneralName;

    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem).ok()?;
    let cert = pem.parse_x509().ok()?;

    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let GeneralName::DNSName(d) = gn {
                names.push(d.to_string());
            }
        }
    }
    Some(names)
}

pub struct Table<C> {
    name_to_cert: HashMap<String, Vec<Arc<C>>>,
}

impl<C: HasDnsNames> Table<C> {
    pub fn empty() -> Self {
        Self {
            name_to_cert: HashMap::new(),
        }
    }

    /// Build the SAN index. CN is intentionally ignored (deprecated), matching Go.
    pub fn build(certs: Vec<Arc<C>>) -> Self {
        let mut name_to_cert: HashMap<String, Vec<Arc<C>>> = HashMap::new();
        for c in &certs {
            for san in c.dns_names() {
                name_to_cert.entry(san.clone()).or_default().push(c.clone());
            }
        }
        Self { name_to_cert }
    }

    /// SAN names this table can serve (exact + wildcard keys), for debug introspection.
    pub fn names(&self) -> Vec<&str> {
        self.name_to_cert.keys().map(String::as_str).collect()
    }

    /// Resolve a server name to a certificate: exact match, then single-label
    /// wildcard. Returns `None` when nothing matches.
    pub fn get(&self, server_name: &str) -> Option<Arc<C>> {
        // Normalize: a fully-qualified SNI may carry a trailing dot
        // (`host.example.com.`), and SNI is case-insensitive. Without this an
        // FQDN client would miss every cert and get the self-signed fallback.
        let name = server_name.trim_end_matches('.').to_ascii_lowercase();

        if let Some(certs) = self.name_to_cert.get(&name) {
            if let Some(c) = certs.first() {
                return Some(c.clone());
            }
        }

        // wildcard: replace the leftmost label with '*' (matches exactly one label)
        if let Some(i) = name.find('.') {
            let wildcard = format!("*{}", &name[i..]);
            if let Some(certs) = self.name_to_cert.get(&wildcard) {
                return certs.first().cloned();
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCert {
        id: &'static str,
        names: Vec<String>,
    }
    impl HasDnsNames for TestCert {
        fn dns_names(&self) -> &[String] {
            &self.names
        }
    }
    fn cert(id: &'static str, names: &[&str]) -> Arc<TestCert> {
        Arc::new(TestCert {
            id,
            names: names.iter().map(|s| s.to_string()).collect(),
        })
    }

    #[test]
    fn empty() {
        let t = Table::<TestCert>::empty();
        assert!(t.get("example.com").is_none());
    }

    #[test]
    fn exact() {
        let t = Table::build(vec![
            cert("exact", &["example.com"]),
            cert("wild", &["*.example.com"]),
        ]);
        assert_eq!(t.get("example.com").unwrap().id, "exact");
    }

    #[test]
    fn wildcard() {
        let t = Table::build(vec![
            cert("exact", &["example.com"]),
            cert("wild", &["*.example.com"]),
        ]);
        assert_eq!(t.get("www.example.com").unwrap().id, "wild");
    }

    #[test]
    fn multi_san_cert() {
        let t = Table::build(vec![cert(
            "c",
            &["secure.example.com", "*.wild.example.com"],
        )]);
        assert_eq!(t.get("secure.example.com").unwrap().id, "c"); // exact SAN
        assert_eq!(t.get("foo.wild.example.com").unwrap().id, "c"); // wildcard SAN
        assert!(t.get("other.example.com").is_none()); // no match
        assert!(t.get("localhost").is_none()); // single-label name must not panic
    }

    #[test]
    fn case_insensitive() {
        let t = Table::build(vec![cert("c", &["example.com"])]);
        assert_eq!(t.get("EXAMPLE.com").unwrap().id, "c");
    }

    #[test]
    fn sni_normalization_and_genuine_misses() {
        let t = Table::build(vec![cert("c", &["api.example.com"])]);
        assert!(t.get("api.example.com").is_some(), "exact hostname matches");
        // a trailing-dot FQDN is normalized and now matches (was a fallback miss)
        assert!(
            t.get("api.example.com.").is_some(),
            "trailing-dot FQDN matches after normalization"
        );
        assert!(t.get("API.Example.COM.").is_some(), "case + trailing dot");
        // genuine misses still fall back: empty SNI / IP-literal SNI
        assert!(
            t.get("").is_none(),
            "empty SNI (no SNI / IP connect) misses"
        );
        assert!(t.get("10.0.0.5").is_none(), "IP-literal SNI misses");
    }
}
