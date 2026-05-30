//! Background cert refresh: on startup and then on a timer, fetch each served
//! domain's cert from the control plane (with ETag revalidation) and swap it into
//! the store. A fetch failure is **fail-static** — the edge keeps serving its
//! cached cert and retries next tick. See EDGE.md "Rotation ordering".

use std::sync::Arc;
use std::time::Duration;

use crate::certstore::CertStore;
use crate::cp::{CertFetch, CpClient};

/// Fetch every domain once. Returns how many are now cached (for the startup log).
pub async fn refresh_all(cp: &CpClient, store: &CertStore, domains: &[String]) -> usize {
    for d in domains {
        refresh_one(cp, store, d).await;
    }
    store.len()
}

/// Fetch one domain's cert from the control plane (ETag-revalidated) and swap it
/// into the store; fail-static on error. Used by the periodic loop and by the
/// on-demand TLS path (serve-all mode).
pub async fn refresh_one(cp: &CpClient, store: &CertStore, domain: &str) {
    let etag = store.etag(domain);
    match cp.fetch_cert(domain, etag.as_deref()).await {
        Ok(CertFetch::Unchanged) => {}
        Ok(CertFetch::Updated {
            chain_pem,
            key_pem,
            etag,
        }) => {
            if store.update(domain, chain_pem, key_pem, etag) {
                tracing::info!(domain, "edge: cert updated");
            } else {
                tracing::warn!(domain, "edge: cert PEM unparseable; keeping cached copy");
            }
        }
        Err(e) => {
            // Fail static: keep whatever we already serve for this domain.
            tracing::warn!(domain, error = %e, "edge: cert fetch failed; keeping cached copy");
        }
    }
}

/// Run the refresh loop forever on the current runtime. Each tick refreshes the
/// configured `domains` PLUS whatever is currently cached (deduped) — so
/// on-demand-fetched domains (serve-all mode, empty `domains`) keep rotating too.
pub async fn run(cp: CpClient, store: Arc<CertStore>, domains: Vec<String>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    // first tick fires immediately; skip it since startup already did a full fetch
    tick.tick().await;
    loop {
        tick.tick().await;
        let mut seen = std::collections::HashSet::new();
        for d in domains.iter().cloned().chain(store.keys()) {
            if seen.insert(d.clone()) {
                refresh_one(&cp, &store, &d).await;
            }
        }
    }
}
