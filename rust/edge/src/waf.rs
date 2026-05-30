//! Edge-side WAF: holds the compiled global baseline plus tenant zones fetched
//! from the control plane, and evaluates them per request. Reuses
//! `controller::waf` verbatim (the same CEL engine the conformance corpus
//! guards), so a rule blocks identically at the edge and at parapet. parapet
//! still re-runs the full WAF — the edge is an early-drop layer, not the
//! authority (see EDGE.md).
//!
//! Eval order mirrors the controller: **global first** (authoritative baseline),
//! then the **zone** bound to the request host (if any). Zone resolution is
//! host-level at the edge; parapet does path-precise zone resolution upstream.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use controller::waf::{parse_rules, Action, AsnDb, Decision, GeoIp, RequestData, Waf, WafConfig};

/// The compiled rulesets + metadata. The global ruleset and each zone are `Waf`
/// instances (rules behind their own ArcSwap); the zone map and host→zone map are
/// themselves ArcSwapped so request-path reads are lock-free. The `Mutex` only
/// guards the small ETag/generation metadata touched by the refresh loop.
///
/// The edge is the first hop, so it resolves `request.country`/`request.asn` from
/// the TRUE client IP. The GeoIP/ASN DBs load once at startup (immutable).
pub struct EdgeWaf {
    global: Waf,
    zones: ArcSwap<HashMap<String, Arc<Waf>>>, // zoneKey -> compiled zone
    host_zone: ArcSwap<HashMap<String, String>>, // host -> zoneKey
    cfg: WafConfig,
    meta: Mutex<WafMeta>,
    geoip: Option<GeoIp>,
    asndb: Option<AsnDb>,
}

#[derive(Default)]
struct WafMeta {
    etag: Option<String>,
    generation: u64,
}

impl EdgeWaf {
    pub fn new() -> Self {
        Self::with_geo(None, None)
    }

    pub fn with_geo(geoip: Option<GeoIp>, asndb: Option<AsnDb>) -> Self {
        Self {
            global: Waf::new(),
            zones: ArcSwap::from_pointee(HashMap::new()),
            host_zone: ArcSwap::from_pointee(HashMap::new()),
            cfg: WafConfig::default(),
            meta: Mutex::new(WafMeta::default()),
            geoip,
            asndb,
        }
    }

    pub fn country_of(&self, ip: Option<IpAddr>) -> String {
        match &self.geoip {
            Some(g) => ip.and_then(|ip| g.country(ip)).unwrap_or_else(|| "XX".to_string()),
            None => String::new(),
        }
    }

    pub fn asn_of(&self, ip: Option<IpAddr>) -> i64 {
        match &self.asndb {
            Some(db) => ip.map(|ip| db.asn(ip)).unwrap_or(0),
            None => 0,
        }
    }

    pub fn etag(&self) -> Option<String> {
        self.meta.lock().unwrap().etag.clone()
    }

    /// Compile and install a fetched payload: the global ruleset, the zones, and
    /// the host→zone bindings. All-or-nothing PER ruleset (a bad global or a bad
    /// zone keeps that ruleset's last-good copy); the host→zone map is swapped
    /// wholesale. Reuses an existing zone instance when present so a bad zone edit
    /// keeps its last-good rules (mirrors the controller). Returns the first
    /// compile error encountered (the rest still apply — fail-static per ruleset).
    pub fn update(
        &self,
        generation: u64,
        global_yaml: String,
        zones_yaml: HashMap<String, String>,
        host_zone: HashMap<String, String>,
        etag: Option<String>,
    ) -> Result<(), String> {
        let mut first_err: Option<String> = None;

        // global
        if let Err(e) = parse_rules(&[global_yaml]).and_then(|r| self.global.set_rules(&r)) {
            first_err.get_or_insert(format!("global: {e}"));
        }

        // zones: reuse the existing Arc<Waf> per key so a bad edit keeps last-good.
        let cur = self.zones.load();
        let mut new_zones: HashMap<String, Arc<Waf>> = HashMap::with_capacity(zones_yaml.len());
        for (key, yaml) in zones_yaml {
            let z = cur.get(&key).cloned().unwrap_or_else(|| Arc::new(Waf::new()));
            if let Err(e) = parse_rules(&[yaml]).and_then(|r| z.set_rules(&r)) {
                first_err.get_or_insert(format!("zone {key}: {e}"));
            }
            new_zones.insert(key, z);
        }
        self.zones.store(Arc::new(new_zones));
        self.host_zone.store(Arc::new(host_zone));

        let mut m = self.meta.lock().unwrap();
        m.etag = etag;
        m.generation = generation;

        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Evaluate the global ruleset. `on_match` fires per matched rule.
    pub fn evaluate_global(&self, req: &RequestData, on_match: impl FnMut(&str, Action)) -> Decision {
        self.global.evaluate(req, &self.cfg, on_match)
    }

    /// Evaluate the zone bound to `host` (if any). Resolution is host-level:
    /// `host → zoneKey → zone`. Returns `Pass` when the host binds no zone or the
    /// zone has no rules (so the caller forwards).
    pub fn evaluate_zone(&self, host: &str, req: &RequestData, on_match: impl FnMut(&str, Action)) -> Decision {
        let hz = self.host_zone.load();
        let Some(key) = hz.get(host) else {
            return Decision::Pass;
        };
        let zones = self.zones.load();
        match zones.get(key) {
            Some(z) => z.evaluate(req, &self.cfg, on_match),
            None => Decision::Pass,
        }
    }

    /// True when nothing is loaded at all (no global rules and no host bindings) —
    /// lets the proxy skip building the request map entirely.
    pub fn is_empty(&self) -> bool {
        self.global.is_empty() && self.host_zone.load().is_empty()
    }
}

impl Default for EdgeWaf {
    fn default() -> Self {
        Self::new()
    }
}
