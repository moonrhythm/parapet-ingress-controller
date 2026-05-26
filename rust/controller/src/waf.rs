//! Web Application Firewall — CEL-rule engine, the Rust port of the Go
//! controller's `parapet/pkg/waf` + `wafrule/` (see `WAF.md`). Behind the `waf`
//! cargo feature (enabled by both `proxy` and `cluster`) so `cel`/`regex` stay
//! out of the fast routing core.
//!
//! A [`WafRegistry`] holds the always-on `global` ruleset plus a hot-swappable
//! map of tenant `zones`. Each [`Waf`] keeps its compiled rules behind an
//! `ArcSwap` (the Rust analog of the Go controller's `atomic.Pointer` swap), so
//! [`Waf::set_rules`] replaces a ruleset lock-free and all-or-nothing: if any
//! rule fails to compile the previous good ruleset stays live.
//!
//! # Intentional divergences from cel-go (documented, like the retry note)
//! - **Cost limit**: cel-rust has none. The per-request `eval_timeout` is checked
//!   *between* rules (cel-rust eval isn't interruptible mid-expression); inputs
//!   are small maps and `regexMatch` uses the RE2-style `regex` crate (linear),
//!   so a single rule can't blow up. cel-go's per-op cost cap has no equivalent.
//! - **Body inspection** is phase 2: `request.body` is always empty here, matching
//!   the Go default (`InspectBody=0`).
//! - **Non-bool result / missing map key** surface as a runtime eval error
//!   (fail-open by default) rather than a compile-time type error — cel-rust is
//!   dynamically typed, so there's no compile-time `OutputType` check.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use cel::{Context, ExecutionError, Program, Value};
use ipnet::IpNet;
use k8s_openapi::api::core::v1::ConfigMap;
use maxminddb::{geoip2, Reader};
use regex::Regex;
use serde::Deserialize;

/// Label key marking a ConfigMap as WAF input; its value is the role.
pub const WAF_LABEL_KEY: &str = "parapet.moonrhythm.io/waf";
const WAF_ROLE_GLOBAL: &str = "global";
const WAF_ROLE_ZONE: &str = "zone";

/// What to do when a rule's expression evaluates true. Mirrors `waf.Action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Action {
    /// Record the match and keep evaluating (shadow rules). The default.
    #[default]
    Log,
    /// Short-circuit *this ruleset* and let the request proceed (allowlists).
    Allow,
    /// Terminate the request with the rule's status/message.
    Block,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Log => "log",
            Action::Allow => "allow",
            Action::Block => "block",
        }
    }
}

/// The outcome of evaluating a ruleset against a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// No block fired (no match, an allow short-circuit, or fail-open).
    Pass,
    /// A block rule fired (or fail-closed): respond with this status/body.
    Block { status: u16, message: String },
}

/// Tunables shared by the global ruleset and every zone. Mirrors the WAF env.
#[derive(Debug, Clone)]
pub struct WafConfig {
    /// On a rule evaluation error: fail-closed (500) vs fail-open (skip + allow).
    pub fail_closed: bool,
    /// Per-request deadline for the whole ruleset, checked between rules.
    pub eval_timeout: Duration,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            fail_closed: false,
            eval_timeout: Duration::from_millis(5),
        }
    }
}

/// The `request.*` fields exposed to CEL expressions. Built per request by the
/// proxy (only when a ruleset is non-empty), mirroring Go's `buildRequestMap`.
#[derive(Debug, Default, Clone)]
pub struct RequestData {
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: String,
    pub uri: String,
    pub proto: String,
    pub scheme: String,
    pub remote_ip: String,
    /// ISO 3166-1 alpha-2 country (GeoIP). "" when GeoIP is off, "XX" when the
    /// DB is loaded but the IP can't be resolved. Exposed as `request.country`.
    pub country: String,
    pub content_length: i64,
    pub headers: HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub args: HashMap<String, String>,
    pub user_agent: String,
    pub referer: String,
    pub body: String,
}

/// A parsed (not yet compiled) rule — the YAML DTO plus the resolved [`Action`].
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub expression: String,
    pub action: Action,
    pub status: u16,
    pub message: String,
    pub priority: i64,
}

#[derive(Debug, Deserialize)]
struct RuleDoc {
    #[serde(default)]
    rules: Vec<RuleSpec>,
}

#[derive(Debug, Deserialize)]
struct RuleSpec {
    #[serde(default)]
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    expression: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    status: u16,
    #[serde(default)]
    message: String,
    #[serde(default)]
    priority: i64,
}

fn parse_action(s: &str) -> Result<Action, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "log" => Ok(Action::Log),
        "allow" => Ok(Action::Allow),
        "block" => Ok(Action::Block),
        other => Err(format!("unknown action {other:?} (want log|allow|block)")),
    }
}

/// Parse one or more YAML rule documents (each a ConfigMap data value) into
/// [`Rule`]s. Errors from any document are collected and returned joined; the
/// caller hands the result to [`Waf::set_rules`], which does the compile-time
/// validation (empty/duplicate id, uncompilable expression) all-or-nothing.
pub fn parse_rules(docs: &[String]) -> Result<Vec<Rule>, String> {
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for doc in docs {
        if doc.trim().is_empty() {
            continue;
        }
        let parsed: RuleDoc = match serde_yaml::from_str(doc) {
            Ok(d) => d,
            Err(e) => {
                errs.push(format!("parse document: {e}"));
                continue;
            }
        };
        for (i, spec) in parsed.rules.into_iter().enumerate() {
            match parse_action(&spec.action) {
                Ok(action) => out.push(Rule {
                    id: spec.id,
                    description: spec.description,
                    expression: spec.expression,
                    action,
                    status: spec.status,
                    message: spec.message,
                    priority: spec.priority,
                }),
                Err(e) => errs.push(format!("rule[{i}] {:?}: {e}", spec.id)),
            }
        }
    }
    if errs.is_empty() {
        Ok(out)
    } else {
        Err(errs.join("; "))
    }
}

struct CompiledRule {
    id: String,
    action: Action,
    status: u16,
    message: String,
    priority: i64,
    program: Program,
}

#[derive(Default)]
struct Ruleset {
    rules: Vec<CompiledRule>,
}

fn compile(rules: &[Rule]) -> Result<Vec<CompiledRule>, String> {
    let mut compiled = Vec::with_capacity(rules.len());
    let mut errs = Vec::new();
    let mut seen = HashSet::new();
    for (i, r) in rules.iter().enumerate() {
        if r.id.is_empty() {
            errs.push(format!("rule[{i}]: missing id"));
            continue;
        }
        if !seen.insert(r.id.clone()) {
            errs.push(format!("rule {:?}: duplicate id", r.id));
            continue;
        }
        if r.expression.trim().is_empty() {
            errs.push(format!("rule {:?}: empty expression", r.id));
            continue;
        }
        match Program::compile(&r.expression) {
            Ok(program) => compiled.push(CompiledRule {
                id: r.id.clone(),
                action: r.action,
                status: if r.status == 0 { 403 } else { r.status },
                message: if r.message.is_empty() {
                    "Forbidden".to_string()
                } else {
                    r.message.clone()
                },
                priority: r.priority,
                program,
            }),
            Err(e) => errs.push(format!("rule {:?}: compile: {e}", r.id)),
        }
    }
    if !errs.is_empty() {
        return Err(errs.join("; "));
    }
    // Stable sort by priority so equal priorities keep declaration order
    // (matches Go's sort.SliceStable).
    compiled.sort_by_key(|c| c.priority);
    Ok(compiled)
}

/// One ruleset (the global baseline, or a single zone). Rules live behind an
/// `ArcSwap` so [`set_rules`](Waf::set_rules) is a lock-free replace.
pub struct Waf {
    rules: ArcSwap<Ruleset>,
}

impl Default for Waf {
    fn default() -> Self {
        Self {
            rules: ArcSwap::from_pointee(Ruleset::default()),
        }
    }
}

impl Waf {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compile and atomically install `rules`. All-or-nothing: on any compile
    /// error the previous ruleset stays live and the error is returned.
    pub fn set_rules(&self, rules: &[Rule]) -> Result<(), String> {
        let compiled = compile(rules)?;
        self.rules.store(Arc::new(Ruleset { rules: compiled }));
        Ok(())
    }

    /// Currently-loaded rule ids in evaluation order (introspection / tests).
    pub fn rule_ids(&self) -> Vec<String> {
        self.rules
            .load()
            .rules
            .iter()
            .map(|r| r.id.clone())
            .collect()
    }

    /// True when no rules are loaded (a cheap pre-check so the proxy can skip
    /// building the request map when there's nothing to evaluate).
    pub fn is_empty(&self) -> bool {
        self.rules.load().rules.is_empty()
    }

    /// Evaluate the ruleset against `req`. `on_match` is invoked for every rule
    /// that fires (any action), letting the caller record metrics/logs without
    /// this module depending on the proxy's metric registry.
    pub fn evaluate(
        &self,
        req: &RequestData,
        cfg: &WafConfig,
        mut on_match: impl FnMut(&str, Action),
    ) -> Decision {
        let rs = self.rules.load();
        if rs.rules.is_empty() {
            return Decision::Pass;
        }

        let mut ctx = Context::default();
        register_functions(&mut ctx);
        // infallible: request_value always yields a Value::Map
        ctx.add_variable_from_value("request", request_value(req));

        let start = Instant::now();
        for rule in &rs.rules {
            // Deadline is checked between rules: cel-rust eval isn't interruptible
            // mid-expression. Fail-open skips the rest (Go default); fail-closed 500s.
            if start.elapsed() > cfg.eval_timeout {
                return if cfg.fail_closed {
                    Decision::Block {
                        status: 500,
                        message: "WAF Error".to_string(),
                    }
                } else {
                    Decision::Pass
                };
            }
            match rule.program.execute(&ctx) {
                Ok(Value::Bool(true)) => {
                    on_match(&rule.id, rule.action);
                    match rule.action {
                        Action::Allow => return Decision::Pass,
                        Action::Block => {
                            return Decision::Block {
                                status: rule.status,
                                message: rule.message.clone(),
                            }
                        }
                        Action::Log => {}
                    }
                }
                Ok(Value::Bool(false)) => {}
                // Non-bool result or an eval error (bad regex, missing map key,
                // type mismatch): treat as a rule error — fail-open by default.
                Ok(_) | Err(_) => {
                    if cfg.fail_closed {
                        return Decision::Block {
                            status: 500,
                            message: "WAF Error".to_string(),
                        };
                    }
                }
            }
        }
        Decision::Pass
    }
}

/// A loaded MaxMind GeoLite2/GeoIP2 country database. Resolves a client IP to
/// its ISO 3166-1 alpha-2 country code for `request.country`.
pub struct GeoIp {
    reader: Reader<Vec<u8>>,
}

impl GeoIp {
    /// Open a `.mmdb` file (the GeoLite2-Country DB). Read into memory once.
    pub fn open(path: &str) -> Result<Self, String> {
        Reader::open_readfile(path)
            .map(|reader| Self { reader })
            .map_err(|e| format!("open {path}: {e}"))
    }

    /// ISO country code for `ip`, or `None` if not found / DB has no country.
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        let res = self.reader.lookup(ip).ok()?;
        let country = res.decode::<geoip2::Country>().ok()??;
        country.country.iso_code.map(str::to_string)
    }
}

/// Holds the global baseline ruleset plus the tenant zone registry. Lives in
/// [`crate::shared::Shared`]; fed by the ConfigMap watcher, read by the proxy.
pub struct WafRegistry {
    config: ArcSwap<WafConfig>,
    global: Waf,
    zones: ArcSwap<HashMap<String, Arc<Waf>>>,
    geoip: ArcSwapOption<GeoIp>,
}

impl Default for WafRegistry {
    fn default() -> Self {
        Self {
            config: ArcSwap::from_pointee(WafConfig::default()),
            global: Waf::default(),
            zones: ArcSwap::from_pointee(HashMap::new()),
            geoip: ArcSwapOption::empty(),
        }
    }
}

impl WafRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the tunables (from env) before serving.
    pub fn configure(&self, cfg: WafConfig) {
        self.config.store(Arc::new(cfg));
    }

    /// Install the GeoIP database (from `WAF_GEOIP_DB`) before serving.
    pub fn set_geoip(&self, geoip: GeoIp) {
        self.geoip.store(Some(Arc::new(geoip)));
    }

    /// Resolve a client IP to its ISO country code for `request.country`.
    /// Returns "" when GeoIP is disabled (no DB) — matching the Go controller's
    /// nil resolver — and "XX" when the DB is loaded but the IP can't be
    /// resolved (private range, missing, parse failure), so a rule can treat
    /// "unknown" explicitly without ever seeing a missing key.
    pub fn country_of(&self, ip: Option<IpAddr>) -> String {
        match self.geoip.load_full() {
            None => String::new(),
            Some(g) => ip
                .and_then(|ip| g.country(ip))
                .unwrap_or_else(|| "XX".to_string()),
        }
    }

    /// Replace the global ruleset (all-or-nothing).
    pub fn set_global_rules(&self, rules: &[Rule]) -> Result<(), String> {
        self.global.set_rules(rules)
    }

    /// True when the global baseline has any rules loaded (request-path pre-check).
    pub fn global_has_rules(&self) -> bool {
        !self.global.is_empty()
    }

    /// Look up a zone's compiled WAF by registry key (`<namespace>/<name>`).
    pub fn zone(&self, key: &str) -> Option<Arc<Waf>> {
        self.zones.load().get(key).cloned()
    }

    /// Atomically swap the whole zone registry.
    pub fn set_zones(&self, zones: HashMap<String, Arc<Waf>>) {
        self.zones.store(Arc::new(zones));
    }

    /// Evaluate the global ruleset (always-on baseline).
    pub fn evaluate_global(
        &self,
        req: &RequestData,
        on_match: impl FnMut(&str, Action),
    ) -> Decision {
        self.global.evaluate(req, &self.config.load(), on_match)
    }

    /// Evaluate a resolved zone WAF (from [`zone`](Self::zone)).
    pub fn evaluate_zone(
        &self,
        zone: &Waf,
        req: &RequestData,
        on_match: impl FnMut(&str, Action),
    ) -> Decision {
        zone.evaluate(req, &self.config.load(), on_match)
    }
}

/// Rebuild the global ruleset and the zone registry from the watched
/// ConfigMaps. Global rules are honored only from `pod_namespace` (platform-
/// owned baseline); zones key on `<namespace>/<name>`. Bad config is kept
/// all-or-nothing by `set_rules` — the previous good ruleset stays live, and a
/// zone reuses its existing instance so a broken edit keeps its last-good rules.
/// Mirrors the Go controller's `reloadWAFDebounced`; decoupled from the router.
pub fn reconcile_configmaps(reg: &WafRegistry, cms: &[Arc<ConfigMap>], pod_namespace: &str) {
    let mut global_docs: Vec<String> = Vec::new();
    let mut zone_docs: HashMap<String, Vec<String>> = HashMap::new();

    for cm in cms {
        let role = cm
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(WAF_LABEL_KEY))
            .map(String::as_str)
            .unwrap_or("");
        let ns = cm.metadata.namespace.as_deref().unwrap_or("");
        let name = cm.metadata.name.as_deref().unwrap_or("");
        match role {
            WAF_ROLE_GLOBAL => {
                if ns != pod_namespace {
                    eprintln!(
                        "[waf] ignoring global ruleset outside controller namespace: {ns}/{name}"
                    );
                    continue;
                }
                global_docs.extend(config_data_values(cm));
            }
            WAF_ROLE_ZONE => {
                zone_docs
                    .entry(format!("{ns}/{name}"))
                    .or_default()
                    .extend(config_data_values(cm));
            }
            _ => {}
        }
    }

    match parse_rules(&global_docs) {
        Ok(rules) => {
            if let Err(e) = reg.set_global_rules(&rules) {
                eprintln!("[waf] global ruleset rejected, keeping previous: {e}");
            }
        }
        Err(e) => eprintln!("[waf] invalid global ruleset, keeping previous: {e}"),
    }

    let mut zones = HashMap::with_capacity(zone_docs.len());
    for (key, docs) in zone_docs {
        // Reuse the existing instance so a bad edit keeps its last-good ruleset.
        let waf = reg.zone(&key).unwrap_or_else(|| Arc::new(Waf::new()));
        match parse_rules(&docs) {
            Ok(rules) => {
                if let Err(e) = waf.set_rules(&rules) {
                    eprintln!("[waf] zone {key} rejected, keeping previous: {e}");
                }
            }
            Err(e) => eprintln!("[waf] zone {key} invalid, keeping previous: {e}"),
        }
        zones.insert(key, waf);
    }
    reg.set_zones(zones);
}

/// ConfigMap `data` values in key order. `data` is a `BTreeMap`, so values come
/// out sorted by key — deterministic rule order across reloads (matches the Go
/// controller's `sortedDataValues`).
fn config_data_values(cm: &ConfigMap) -> Vec<String> {
    cm.data
        .as_ref()
        .map(|d| d.values().cloned().collect())
        .unwrap_or_default()
}

// ---- CEL request map + custom functions ------------------------------------

fn request_value(d: &RequestData) -> Value {
    let mut m: HashMap<String, Value> = HashMap::with_capacity(16);
    m.insert("method".into(), d.method.clone().into());
    m.insert("host".into(), d.host.clone().into());
    m.insert("path".into(), d.path.clone().into());
    m.insert("query".into(), d.query.clone().into());
    m.insert("uri".into(), d.uri.clone().into());
    m.insert("proto".into(), d.proto.clone().into());
    m.insert("scheme".into(), d.scheme.clone().into());
    m.insert("remote_ip".into(), d.remote_ip.clone().into());
    m.insert("country".into(), d.country.clone().into());
    m.insert("content_length".into(), Value::Int(d.content_length));
    m.insert("headers".into(), str_map_value(&d.headers));
    m.insert("cookies".into(), str_map_value(&d.cookies));
    m.insert("args".into(), str_map_value(&d.args));
    m.insert("user_agent".into(), d.user_agent.clone().into());
    m.insert("referer".into(), d.referer.clone().into());
    m.insert("body".into(), d.body.clone().into());
    Value::from(m)
}

fn str_map_value(m: &HashMap<String, String>) -> Value {
    let converted: HashMap<String, Value> = m
        .iter()
        .map(|(k, v)| (k.clone(), Value::from(v.clone())))
        .collect();
    Value::from(converted)
}

fn want_string(v: &Value, func: &str) -> Result<Arc<String>, ExecutionError> {
    match v {
        Value::String(s) => Ok(s.clone()),
        other => Err(ExecutionError::function_error(
            func,
            format!("expected string, got {other:?}"),
        )),
    }
}

fn want_string_list(v: &Value, func: &str) -> Result<Vec<Arc<String>>, ExecutionError> {
    match v {
        Value::List(items) => items.iter().map(|it| want_string(it, func)).collect(),
        other => Err(ExecutionError::function_error(
            func,
            format!("expected list, got {other:?}"),
        )),
    }
}

/// Register the 7 custom functions the Go WAF exposes, using the same names so
/// rule strings are portable: `ipInCidr`, `regexMatch`, `containsAny`,
/// `hasPrefixAny`, `lower`, `upper`, `urlDecode`. Standard methods
/// (`contains`, `startsWith`, `matches`, …) come from `Context::default()`.
fn register_functions(ctx: &mut Context) {
    ctx.add_function(
        "ipInCidr",
        |ip: Value, cidr: Value| -> Result<Value, ExecutionError> {
            let ip = want_string(&ip, "ipInCidr")?;
            let cidr = want_string(&cidr, "ipInCidr")?;
            let net: IpNet = cidr
                .as_str()
                .parse()
                .map_err(|e| ExecutionError::function_error("ipInCidr", e))?;
            let Ok(addr) = ip.as_str().parse::<IpAddr>() else {
                return Ok(Value::Bool(false));
            };
            Ok(Value::Bool(net.contains(&addr)))
        },
    );
    ctx.add_function(
        "regexMatch",
        |s: Value, pat: Value| -> Result<Value, ExecutionError> {
            let s = want_string(&s, "regexMatch")?;
            let pat = want_string(&pat, "regexMatch")?;
            match compiled_regex(&pat) {
                Some(re) => Ok(Value::Bool(re.is_match(s.as_str()))),
                None => Err(ExecutionError::function_error(
                    "regexMatch",
                    format!("invalid pattern {:?}", pat.as_str()),
                )),
            }
        },
    );
    ctx.add_function(
        "containsAny",
        |s: Value, list: Value| -> Result<Value, ExecutionError> {
            let s = want_string(&s, "containsAny")?;
            let list = want_string_list(&list, "containsAny")?;
            Ok(Value::Bool(
                list.iter()
                    .any(|sub| !sub.is_empty() && s.contains(sub.as_str())),
            ))
        },
    );
    ctx.add_function(
        "hasPrefixAny",
        |s: Value, list: Value| -> Result<Value, ExecutionError> {
            let s = want_string(&s, "hasPrefixAny")?;
            let list = want_string_list(&list, "hasPrefixAny")?;
            Ok(Value::Bool(
                list.iter()
                    .any(|p| !p.is_empty() && s.starts_with(p.as_str())),
            ))
        },
    );
    ctx.add_function("lower", |s: Value| -> Result<Value, ExecutionError> {
        Ok(Value::from(want_string(&s, "lower")?.to_lowercase()))
    });
    ctx.add_function("upper", |s: Value| -> Result<Value, ExecutionError> {
        Ok(Value::from(want_string(&s, "upper")?.to_uppercase()))
    });
    ctx.add_function("urlDecode", |s: Value| -> Result<Value, ExecutionError> {
        let s = want_string(&s, "urlDecode")?;
        // Go's url.QueryUnescape returns "" on a malformed escape.
        Ok(Value::from(query_unescape(s.as_str()).unwrap_or_default()))
    });
}

/// Process-wide cache of compiled regexes (keyed by pattern). `None` caches a
/// compile failure so a bad pattern isn't recompiled every request. Mirrors the
/// Go WAF's `regexCache`. `regex::Regex` is RE2-style (linear), like Go's RE2.
fn compiled_regex(pattern: &str) -> Option<Regex> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Regex>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(r) = map.get(pattern) {
        return r.clone();
    }
    let compiled = Regex::new(pattern).ok();
    map.insert(pattern.to_string(), compiled.clone());
    compiled
}

/// Percent-decode like Go's `url.QueryUnescape`: `+` -> space, `%XX` -> byte,
/// and `None` on a malformed escape. Bytes are then lossily decoded as UTF-8.
/// Public so the proxy can decode query args the same way Go's `url.Query` does.
pub fn query_unescape(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 3 > bytes.len() {
                    return None;
                }
                let h = hex_val(bytes[i + 1])?;
                let l = hex_val(bytes[i + 2])?;
                out.push((h << 4) | l);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(expr: &str, action: Action) -> Rule {
        Rule {
            id: "r".into(),
            description: String::new(),
            expression: expr.into(),
            action,
            status: 0,
            message: String::new(),
            priority: 0,
        }
    }

    fn waf_with(rules: &[Rule]) -> Waf {
        let w = Waf::new();
        w.set_rules(rules).expect("rules compile");
        w
    }

    fn test_cfg() -> WafConfig {
        // Generous timeout so the between-rules deadline can't make tests flaky.
        WafConfig {
            fail_closed: false,
            eval_timeout: Duration::from_secs(5),
        }
    }

    fn decide(w: &Waf, req: &RequestData) -> Decision {
        w.evaluate(req, &test_cfg(), |_, _| {})
    }

    fn req() -> RequestData {
        RequestData {
            method: "GET".into(),
            host: "example.com".into(),
            path: "/".into(),
            proto: "HTTP/1.1".into(),
            scheme: "http".into(),
            ..Default::default()
        }
    }

    // ---- parsing --------------------------------------------------------

    #[test]
    fn parse_action_variants() {
        assert_eq!(parse_action(""), Ok(Action::Log));
        assert_eq!(parse_action("LOG"), Ok(Action::Log));
        assert_eq!(parse_action(" allow "), Ok(Action::Allow));
        assert_eq!(parse_action("block"), Ok(Action::Block));
        assert!(parse_action("deny").is_err());
    }

    #[test]
    fn parse_rules_concatenates_and_defaults() {
        let docs = vec![
            "rules:\n  - id: a\n    expression: \"true\"\n    action: log".to_string(),
            "rules:\n  - id: b\n    expression: \"false\"".to_string(), // empty action -> log
        ];
        let rules = parse_rules(&docs).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "a");
        assert_eq!(rules[1].action, Action::Log);
    }

    #[test]
    fn parse_rules_reports_bad_action_and_yaml() {
        assert!(
            parse_rules(&["rules:\n  - id: a\n    expression: x\n    action: nuke".into()])
                .unwrap_err()
                .contains("unknown action")
        );
        assert!(parse_rules(&["rules: [ : : :".into()]).is_err());
        // blank documents are skipped
        assert_eq!(parse_rules(&["".into(), "   ".into()]).unwrap().len(), 0);
    }

    // ---- compile / set_rules -------------------------------------------

    #[test]
    fn set_rules_validates_and_sorts() {
        let w = Waf::new();
        // duplicate id
        assert!(w
            .set_rules(&[rule("true", Action::Log), rule("false", Action::Log)])
            .is_err());
        // empty id
        let mut bad = rule("true", Action::Log);
        bad.id = String::new();
        assert!(w.set_rules(&[bad]).is_err());

        // priority ordering (ascending, stable)
        let mk = |id: &str, p: i64| Rule {
            id: id.into(),
            priority: p,
            ..rule("true", Action::Log)
        };
        w.set_rules(&[mk("third", 30), mk("first", 10), mk("second", 20)])
            .unwrap();
        assert_eq!(w.rule_ids(), vec!["first", "second", "third"]);
    }

    #[test]
    fn bad_rule_keeps_last_good() {
        let w = waf_with(&[rule(r#"request.path == "/x""#, Action::Block)]);
        assert_eq!(w.rule_ids(), vec!["r"]);
        // an uncompilable expression is rejected; the previous ruleset survives
        assert!(w
            .set_rules(&[rule("this is not (cel", Action::Block)])
            .is_err());
        assert_eq!(w.rule_ids(), vec!["r"]);
    }

    // ---- actions --------------------------------------------------------

    #[test]
    fn block_allow_log_actions() {
        let mut r = req();
        r.path = "/admin/users".into();

        // block on match
        let w = waf_with(&[rule(r#"request.path.startsWith("/admin")"#, Action::Block)]);
        assert!(matches!(
            decide(&w, &r),
            Decision::Block { status: 403, .. }
        ));

        // non-match passes
        let mut public = req();
        public.path = "/public".into();
        assert_eq!(decide(&w, &public), Decision::Pass);

        // allow short-circuits a later block
        let w = waf_with(&[
            Rule {
                id: "allow".into(),
                priority: 0,
                ..rule(r#"request.headers["x-internal"] == "yes""#, Action::Allow)
            },
            Rule {
                id: "block".into(),
                priority: 10,
                ..rule(r#"request.path.startsWith("/admin")"#, Action::Block)
            },
        ]);
        r.headers.insert("x-internal".into(), "yes".into());
        assert_eq!(decide(&w, &r), Decision::Pass);
    }

    #[test]
    fn custom_block_status_and_message() {
        let w = waf_with(&[Rule {
            status: 401,
            message: "nope".into(),
            ..rule("true", Action::Block)
        }]);
        assert_eq!(
            decide(&w, &req()),
            Decision::Block {
                status: 401,
                message: "nope".into()
            }
        );
    }

    #[test]
    fn fail_open_vs_closed_on_eval_error() {
        // a runtime regex error (pattern from a header, so not constant-folded)
        let w = waf_with(&[rule(
            r#"regexMatch(request.user_agent, request.headers["x-pattern"])"#,
            Action::Block,
        )]);
        let mut r = req();
        r.user_agent = "x".into();
        r.headers.insert("x-pattern".into(), "(unterminated".into());

        // fail-open (default): rule error -> request passes
        assert_eq!(decide(&w, &r), Decision::Pass);
        // fail-closed: rule error -> 500
        let cfg = WafConfig {
            fail_closed: true,
            eval_timeout: Duration::from_secs(5),
        };
        assert!(matches!(
            w.evaluate(&r, &cfg, |_, _| {}),
            Decision::Block { status: 500, .. }
        ));
    }

    #[test]
    fn on_match_fires_for_every_rule() {
        let w = waf_with(&[
            Rule {
                id: "log1".into(),
                priority: 0,
                ..rule(r#"request.method == "GET""#, Action::Log)
            },
            Rule {
                id: "block1".into(),
                priority: 10,
                ..rule("true", Action::Block)
            },
        ]);
        let mut fired = Vec::new();
        let d = w.evaluate(&req(), &test_cfg(), |id, action| {
            fired.push((id.to_string(), action))
        });
        assert!(matches!(d, Decision::Block { .. }));
        assert_eq!(
            fired,
            vec![
                ("log1".to_string(), Action::Log),
                ("block1".to_string(), Action::Block)
            ]
        );
    }

    // ---- shared CEL corpus (mirrors Go waf_test.go) --------------------
    // These assert that identical rule strings behave identically to cel-go.

    fn blocks(expr: &str, setup: impl FnOnce(&mut RequestData)) -> bool {
        let w = waf_with(&[rule(expr, Action::Block)]);
        let mut r = req();
        setup(&mut r);
        matches!(decide(&w, &r), Decision::Block { .. })
    }

    #[test]
    fn corpus_request_variables() {
        assert!(blocks(r#"request.method == "DELETE""#, |r| r.method =
            "DELETE".into()));
        assert!(blocks(r#"request.headers["x-bad"] == "1""#, |r| {
            r.headers.insert("x-bad".into(), "1".into());
        }));
        assert!(blocks(r#"request.user_agent.contains("sqlmap")"#, |r| {
            r.user_agent = "sqlmap/1.0".into();
        }));
        assert!(blocks(r#"request.args["id"] == "../../etc/passwd""#, |r| {
            r.args.insert("id".into(), "../../etc/passwd".into());
        }));
        assert!(blocks(r#"request.cookies["session"] == "stolen""#, |r| {
            r.cookies.insert("session".into(), "stolen".into());
        }));
    }

    #[test]
    fn corpus_custom_functions() {
        // ipInCidr
        assert!(blocks(
            r#"ipInCidr(request.remote_ip, "10.0.0.0/8")"#,
            |r| r.remote_ip = "10.5.6.7".into()
        ));
        assert!(!blocks(
            r#"ipInCidr(request.remote_ip, "10.0.0.0/8")"#,
            |r| r.remote_ip = "8.8.8.8".into()
        ));
        // regexMatch with urlDecode + lower normalisation (SQLi signature)
        assert!(blocks(
            r#"regexMatch(lower(urlDecode(request.query)), "(union\\s+select|or\\s+1=1)")"#,
            |r| r.query = "q=1+UNION+SELECT+pass".into()
        ));
        // containsAny short-circuit
        assert!(blocks(
            r#"containsAny(lower(request.user_agent), ["sqlmap", "nikto", "acunetix"])"#,
            |r| r.user_agent = "Mozilla/5.0 NIKTO scanner".into()
        ));
        // hasPrefixAny
        assert!(blocks(
            r#"hasPrefixAny(request.path, ["/admin", "/internal", "/.git"])"#,
            |r| r.path = "/.git/config".into()
        ));
        // urlDecode normalises percent-encoding
        assert!(blocks(r#"urlDecode(request.query).contains("../")"#, |r| {
            r.query = "file=%2E%2E%2Fetc%2Fpasswd".into()
        }));
        // upper
        assert!(blocks(r#"upper(request.method) == "GET""#, |r| r.method =
            "get".into()));
    }

    #[test]
    fn query_unescape_matches_go_semantics() {
        assert_eq!(query_unescape("a+b").as_deref(), Some("a b"));
        assert_eq!(query_unescape("%2E%2E%2F").as_deref(), Some("../"));
        assert_eq!(
            query_unescape("1+UNION+SELECT").as_deref(),
            Some("1 UNION SELECT")
        );
        // malformed escape -> None (Go returns "")
        assert_eq!(query_unescape("%2"), None);
        assert_eq!(query_unescape("%zz"), None);
    }

    #[test]
    fn empty_ruleset_passes() {
        assert_eq!(decide(&Waf::new(), &req()), Decision::Pass);
    }

    #[test]
    fn corpus_country_field() {
        // request.country is a normalized field; rules filter on it directly,
        // identically to the Go controller (same rule strings).
        assert!(blocks(r#"request.country == "CN""#, |r| r.country = "CN".into()));
        assert!(!blocks(r#"request.country == "CN""#, |r| r.country = "TH".into()));
        assert!(blocks(
            r#"containsAny(request.country, ["CN", "RU", "KP"])"#,
            |r| r.country = "RU".into()
        ));
        // "block all except TH": an unknown country ("XX") is still blocked,
        // and crucially does NOT fail open (request.country is always present).
        assert!(blocks(r#"request.country != "TH""#, |r| r.country = "XX".into()));
    }

    #[test]
    fn country_of_empty_without_db() {
        // No GeoIP DB loaded -> "" for any IP (matches the Go nil resolver).
        let reg = WafRegistry::new();
        assert_eq!(reg.country_of("8.8.8.8".parse().ok()), "");
        assert_eq!(reg.country_of(None), "");
    }
}
