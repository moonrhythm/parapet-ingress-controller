//! In-memory, hot-swappable cert store. Holds the cert+key for each domain the
//! edge serves, indexed for SNI lookup by reusing the controller's
//! `cert::{Table, LoadedCert}` (so exact + single-label-wildcard resolution and
//! the parsed-chain cache behave exactly like parapet). Keys live only here —
//! never written to disk. See EDGE.md "Cert distribution flow".

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use controller::cert::{LoadedCert, Table};

/// One fetched domain's parsed cert plus the ETag it came with (for revalidation).
struct Cached {
    cert: Arc<LoadedCert>,
    etag: Option<String>,
}

pub struct CertStore {
    /// Live SNI index read on the TLS handshake path (lock-free).
    table: ArcSwap<Table<LoadedCert>>,
    /// Source of truth keyed by the *fetch key* (the domain the edge requested),
    /// used to rebuild `table` and to remember each domain's ETag.
    cache: Mutex<HashMap<String, Cached>>,
}

impl CertStore {
    pub fn new() -> Self {
        Self {
            table: ArcSwap::from_pointee(Table::empty()),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// SNI lookup for the handshake: exact, then single-label wildcard.
    pub fn get(&self, sni: &str) -> Option<Arc<LoadedCert>> {
        self.table.load().get(sni)
    }

    /// The ETag currently cached for a fetch key (sent as `If-None-Match`).
    pub fn etag(&self, key: &str) -> Option<String> {
        self.cache
            .lock()
            .unwrap()
            .get(key)
            .and_then(|c| c.etag.clone())
    }

    /// Install/replace the material for a fetch key and atomically rebuild the
    /// SNI index. Returns false if the PEM can't be parsed (caller keeps the old
    /// copy — fail static).
    pub fn update(
        &self,
        key: &str,
        chain_pem: Vec<u8>,
        key_pem: Vec<u8>,
        etag: Option<String>,
    ) -> bool {
        let Some(loaded) = LoadedCert::from_pem(chain_pem, key_pem) else {
            return false;
        };
        let mut cache = self.cache.lock().unwrap();
        cache.insert(
            key.to_string(),
            Cached {
                cert: Arc::new(loaded),
                etag,
            },
        );
        let certs: Vec<Arc<LoadedCert>> = cache.values().map(|c| c.cert.clone()).collect();
        // Rebuild the SAN index from every cached cert and swap it in.
        self.table.store(Arc::new(Table::build(certs)));
        true
    }

    /// Number of domains currently cached (for logging).
    pub fn len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// The fetch keys currently cached. The periodic refresh uses this to keep
    /// on-demand-fetched domains (serve-all mode) rotated, not just a fixed list.
    pub fn keys(&self) -> Vec<String> {
        self.cache.lock().unwrap().keys().cloned().collect()
    }
}

impl Default for CertStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed cert+key PEM pair for the given SANs.
    fn pem(sans: &[&str]) -> (Vec<u8>, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(
            sans.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        (
            ck.cert.pem().into_bytes(),
            ck.key_pair.serialize_pem().into_bytes(),
        )
    }

    #[test]
    fn update_then_sni_match_exact_and_wildcard() {
        let s = CertStore::new();
        let (c1, k1) = pem(&["acme.com"]);
        let (c2, k2) = pem(&["*.acme.com"]);
        assert!(s.update("acme.com", c1, k1, Some("\"e1\"".into())));
        assert!(s.update("*.acme.com", c2, k2, None));

        assert!(s.get("acme.com").is_some(), "exact match");
        assert!(s.get("www.acme.com").is_some(), "single-label wildcard");
        assert!(
            s.get("ACME.com.").is_some(),
            "case + trailing dot normalized"
        );
        assert!(
            s.get("a.b.acme.com").is_none(),
            "wildcard is one label only"
        );
        assert!(s.get("other.com").is_none(), "no match");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn etag_roundtrips_per_fetch_key() {
        let s = CertStore::new();
        let (c, k) = pem(&["acme.com"]);
        s.update("acme.com", c, k, Some("\"abc\"".into()));
        assert_eq!(s.etag("acme.com").as_deref(), Some("\"abc\""));
        assert_eq!(s.etag("missing.com"), None);
    }

    #[test]
    fn unparseable_pem_is_rejected_and_keeps_old() {
        let s = CertStore::new();
        let (c, k) = pem(&["acme.com"]);
        assert!(s.update("acme.com", c, k, Some("\"v1\"".into())));
        // garbage PEM -> update returns false, store unchanged (fail static)
        assert!(!s.update(
            "acme.com",
            b"not a cert".to_vec(),
            b"nope".to_vec(),
            Some("\"v2\"".into())
        ));
        assert!(s.get("acme.com").is_some(), "old cert still served");
        assert_eq!(
            s.etag("acme.com").as_deref(),
            Some("\"v1\""),
            "old etag retained"
        );
    }

    #[test]
    fn update_replaces_cert_for_same_key_and_rebuilds_index() {
        let s = CertStore::new();
        let (c1, k1) = pem(&["acme.com"]);
        s.update("acme.com", c1, k1, Some("\"v1\"".into()));
        // re-fetch the same domain with a fresh cert + new etag
        let (c2, k2) = pem(&["acme.com"]);
        assert!(s.update("acme.com", c2, k2, Some("\"v2\"".into())));
        assert_eq!(s.len(), 1, "same fetch key replaces, not duplicates");
        assert_eq!(s.etag("acme.com").as_deref(), Some("\"v2\""));
        assert!(s.get("acme.com").is_some());
    }
}
