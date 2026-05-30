//! Background WAF refresh: on startup and then on a timer, fetch the global
//! ruleset from the control plane (ETag-revalidated) and swap it into EdgeWaf. A
//! fetch or compile failure is **fail-static** — the edge keeps its last-good
//! ruleset and retries next tick; it never falls open to "no WAF". Mirrors the
//! cert refresh loop (refresh.rs).

use std::sync::Arc;
use std::time::Duration;

use crate::cp::{CpClient, WafFetch};
use crate::waf::EdgeWaf;

/// One fetch. Used both at startup and per tick.
async fn refresh_once(cp: &CpClient, waf: &EdgeWaf) {
    let etag = waf.etag();
    match cp.fetch_waf(etag.as_deref()).await {
        Ok(WafFetch::Unchanged) => {}
        Ok(WafFetch::Updated {
            generation,
            global_rules,
            zones,
            host_zone_map,
            etag,
        }) => match waf.update(generation, global_rules, zones, host_zone_map, etag) {
            Ok(()) => tracing::info!(generation, "edge: WAF rulesets updated"),
            Err(e) => {
                tracing::warn!(error = %e, "edge: a WAF ruleset was rejected; kept last-good (per ruleset)")
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "edge: WAF fetch failed; keeping last-good ruleset");
        }
    }
}

/// Initial blocking fetch (so rules are present before serving), returning
/// whether any rules are now loaded (for the startup log).
pub async fn refresh_initial(cp: &CpClient, waf: &EdgeWaf) -> bool {
    refresh_once(cp, waf).await;
    !waf.is_empty()
}

/// Run the refresh loop forever on the current runtime.
pub async fn run(cp: CpClient, waf: Arc<EdgeWaf>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.tick().await; // first tick is immediate; startup already fetched
    loop {
        tick.tick().await;
        refresh_once(&cp, &waf).await;
    }
}
