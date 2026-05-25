//! Parse the `parapet.moonrhythm.io/*` ingress annotations into a structured
//! [`RouteConfig`]. This is pure parsing only — the request-time *behavior*
//! (redirect, HSTS header, body limit, IP allow-list, path rewrites, auth) is
//! applied later in the proxy phases. Mirrors the parsing in the Go `plugin`
//! package; tests track `plugin_test.go`.

use std::collections::BTreeMap;

use ipnet::IpNet;
use serde::Deserialize;

pub const NS: &str = "parapet.moonrhythm.io";

#[derive(Debug, Default, PartialEq)]
pub struct RouteConfig {
    pub redirect_https: bool,
    pub hsts: Option<Hsts>,
    pub redirect_rules: Vec<RedirectRule>,
    pub ratelimit_s: Option<u32>,
    pub ratelimit_m: Option<u32>,
    pub ratelimit_h: Option<u32>,
    pub body_limit: Option<i64>,
    pub upstream_protocol: UpstreamProtocol,
    pub upstream_host: Option<String>,
    pub upstream_path: Option<UpstreamPath>,
    pub allow_remote: Vec<IpNet>,
    pub strip_prefix: Option<String>,
    pub basic_auth: Option<BasicAuth>,
    pub forward_auth: Option<ForwardAuth>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Hsts {
    Default,
    Preload,
}

#[derive(Debug, PartialEq, Eq, Default)]
pub enum UpstreamProtocol {
    #[default]
    Http,
    Https,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RedirectRule {
    /// Source host, always normalized to end with `/` (the router key).
    pub src_host: String,
    pub status: u16,
    pub target: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct UpstreamPath {
    pub path: String,
    pub raw_query: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BasicAuth {
    pub user: String,
    pub pass: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ForwardAuth {
    pub url: String,
    pub auth_request_headers: Vec<String>,
    pub auth_response_headers: Vec<String>,
}

impl RouteConfig {
    pub fn from_annotations(a: &BTreeMap<String, String>) -> Self {
        let get = |suffix: &str| {
            a.get(&format!("{NS}{suffix}"))
                .map(String::as_str)
                .filter(|s| !s.is_empty())
        };

        RouteConfig {
            redirect_https: get("/redirect-https") == Some("true"),
            hsts: match get("/hsts") {
                None => None,
                Some("preload") => Some(Hsts::Preload),
                Some(_) => Some(Hsts::Default),
            },
            redirect_rules: get("/redirect")
                .map(parse_redirect_rules)
                .unwrap_or_default(),
            ratelimit_s: get("/ratelimit-s").and_then(parse_pos_u32),
            ratelimit_m: get("/ratelimit-m").and_then(parse_pos_u32),
            ratelimit_h: get("/ratelimit-h").and_then(parse_pos_u32),
            body_limit: get("/body-limitrequest").and_then(parse_pos_i64),
            upstream_protocol: match get("/upstream-protocol") {
                Some("https") => UpstreamProtocol::Https,
                _ => UpstreamProtocol::Http, // "", "http", or unknown -> http
            },
            upstream_host: get("/upstream-host").map(str::to_string),
            upstream_path: get("/upstream-path").and_then(parse_upstream_path),
            allow_remote: get("/allow-remote").map(parse_cidrs).unwrap_or_default(),
            strip_prefix: get("/strip-prefix").map(str::to_string),
            basic_auth: get("/basic-auth").and_then(parse_basic_auth),
            forward_auth: get("/forward-auth").and_then(parse_forward_auth),
        }
    }
}

fn parse_pos_u32(s: &str) -> Option<u32> {
    s.parse::<u32>().ok().filter(|n| *n > 0)
}

fn parse_pos_i64(s: &str) -> Option<i64> {
    s.parse::<i64>().ok().filter(|n| *n > 0)
}

fn parse_redirect_rules(s: &str) -> Vec<RedirectRule> {
    let obj: BTreeMap<String, String> = serde_yaml::from_str(s).unwrap_or_default();
    let mut out = Vec::new();
    for (src, target_url) in obj {
        // skip invalid entries; keep the rest (matches Go)
        if src.is_empty() || target_url.is_empty() || src.starts_with('/') {
            continue;
        }
        let src_host = if src.ends_with('/') {
            src
        } else {
            format!("{src}/")
        };

        let mut status = 302u16; // http.StatusFound
        let mut target = target_url.clone();
        if let Some((code, rest)) = target_url.split_once(',') {
            if let Ok(st) = code.parse::<u16>() {
                if st > 0 {
                    status = st;
                    target = rest.to_string();
                }
            }
        }
        out.push(RedirectRule {
            src_host,
            status,
            target,
        });
    }
    out
}

/// Join an upstream path prefix with a request path, mirroring Go's
/// `httputil` `singleJoiningSlash`.
pub fn single_joining_slash(a: &str, b: &str) -> String {
    let aslash = a.ends_with('/');
    let bslash = b.starts_with('/');
    match (aslash, bslash) {
        (true, true) => format!("{a}{}", &b[1..]),
        (false, false) => format!("{a}/{b}"),
        _ => format!("{a}{b}"),
    }
}

fn parse_upstream_path(s: &str) -> Option<UpstreamPath> {
    // Go uses url.ParseRequestURI, which requires an absolute path.
    if !s.starts_with('/') {
        return None;
    }
    let (path, raw_query) = match s.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (s.to_string(), String::new()),
    };
    Some(UpstreamPath { path, raw_query })
}

fn parse_cidrs(s: &str) -> Vec<IpNet> {
    s.split(',')
        .filter_map(|x| x.trim().parse::<IpNet>().ok())
        .collect()
}

fn parse_basic_auth(s: &str) -> Option<BasicAuth> {
    let (user, pass) = s.split_once(':')?;
    if user.is_empty() || pass.is_empty() {
        return None;
    }
    Some(BasicAuth {
        user: user.to_string(),
        pass: pass.to_string(),
    })
}

fn parse_forward_auth(s: &str) -> Option<ForwardAuth> {
    #[derive(Deserialize)]
    struct Raw {
        url: String,
        #[serde(default, rename = "authRequestHeaders")]
        auth_request_headers: Vec<String>,
        #[serde(default, rename = "authResponseHeaders")]
        auth_response_headers: Vec<String>,
    }
    let raw: Raw = serde_yaml::from_str(s).ok()?;
    if raw.url.is_empty() {
        return None;
    }
    Some(ForwardAuth {
        url: raw.url,
        auth_request_headers: raw.auth_request_headers,
        auth_response_headers: raw.auth_response_headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ann(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (format!("{NS}{k}"), v.to_string()))
            .collect()
    }

    #[test]
    fn redirect_https_and_hsts() {
        let c = RouteConfig::from_annotations(&ann(&[
            ("/redirect-https", "true"),
            ("/hsts", "preload"),
        ]));
        assert!(c.redirect_https);
        assert_eq!(c.hsts, Some(Hsts::Preload));

        let c = RouteConfig::from_annotations(&ann(&[("/hsts", "true")]));
        assert_eq!(c.hsts, Some(Hsts::Default));
        assert!(!c.redirect_https);
    }

    #[test]
    fn redirect_rules() {
        let cfg = "\nexample.com: https://www.example.com\napi.example.com: 308,https://www.example.com/api";
        let mut c = RouteConfig::from_annotations(&ann(&[("/redirect", cfg)]));
        c.redirect_rules.sort_by(|a, b| a.src_host.cmp(&b.src_host));
        assert_eq!(
            c.redirect_rules,
            vec![
                RedirectRule {
                    src_host: "api.example.com/".into(),
                    status: 308,
                    target: "https://www.example.com/api".into(),
                },
                RedirectRule {
                    src_host: "example.com/".into(),
                    status: 302,
                    target: "https://www.example.com".into(),
                },
            ]
        );
    }

    #[test]
    fn redirect_rules_skip_invalid() {
        let cfg = "\na.example.com: https://target-a.example.com\nb.example.com: https://target-b.example.com\nbad.example.com: \"\"";
        let c = RouteConfig::from_annotations(&ann(&[("/redirect", cfg)]));
        let hosts: Vec<&str> = c
            .redirect_rules
            .iter()
            .map(|r| r.src_host.as_str())
            .collect();
        assert!(hosts.contains(&"a.example.com/"));
        assert!(hosts.contains(&"b.example.com/"));
        assert!(!hosts.contains(&"bad.example.com/"));
    }

    #[test]
    fn body_limit_valid_and_invalid() {
        assert_eq!(
            RouteConfig::from_annotations(&ann(&[("/body-limitrequest", "1024")])).body_limit,
            Some(1024)
        );
        assert_eq!(
            RouteConfig::from_annotations(&ann(&[("/body-limitrequest", "not-a-number")]))
                .body_limit,
            None
        );
    }

    #[test]
    fn upstream_protocol_and_host() {
        let c = RouteConfig::from_annotations(&ann(&[
            ("/upstream-protocol", "https"),
            ("/upstream-host", "test"),
        ]));
        assert_eq!(c.upstream_protocol, UpstreamProtocol::Https);
        assert_eq!(c.upstream_host.as_deref(), Some("test"));

        // unknown protocol falls back to http
        let c = RouteConfig::from_annotations(&ann(&[("/upstream-protocol", "weird")]));
        assert_eq!(c.upstream_protocol, UpstreamProtocol::Http);
    }

    #[test]
    fn upstream_path_join() {
        let c = RouteConfig::from_annotations(&ann(&[("/upstream-path", "/api")]));
        let up = c.upstream_path.unwrap();
        assert_eq!(up.path, "/api");
        // request-time behavior
        assert_eq!(single_joining_slash(&up.path, "/profile"), "/api/profile");
    }

    #[test]
    fn allow_remote_cidrs() {
        let c = RouteConfig::from_annotations(&ann(&[(
            "/allow-remote",
            "192.168.0.0/24,127.0.0.1/32",
        )]));
        assert_eq!(c.allow_remote.len(), 2);
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert!(c.allow_remote[0].contains(&ip("192.168.0.32")));
        assert!(!c.allow_remote[0].contains(&ip("192.168.1.32")));
    }

    #[test]
    fn strip_prefix_and_basic_auth() {
        let c = RouteConfig::from_annotations(&ann(&[
            ("/strip-prefix", "/api"),
            ("/basic-auth", "user:pass"),
        ]));
        assert_eq!(c.strip_prefix.as_deref(), Some("/api"));
        assert_eq!(
            c.basic_auth,
            Some(BasicAuth {
                user: "user".into(),
                pass: "pass".into()
            })
        );

        // malformed basic-auth is ignored
        assert!(
            RouteConfig::from_annotations(&ann(&[("/basic-auth", "nopassword")]))
                .basic_auth
                .is_none()
        );
        assert!(
            RouteConfig::from_annotations(&ann(&[("/basic-auth", "user:")]))
                .basic_auth
                .is_none()
        );
    }

    #[test]
    fn forward_auth() {
        let cfg = "url: https://auth.example.com/verify\nauthRequestHeaders:\n  - Cookie\nauthResponseHeaders:\n  - X-User";
        let c = RouteConfig::from_annotations(&ann(&[("/forward-auth", cfg)]));
        assert_eq!(
            c.forward_auth,
            Some(ForwardAuth {
                url: "https://auth.example.com/verify".into(),
                auth_request_headers: vec!["Cookie".into()],
                auth_response_headers: vec!["X-User".into()],
            })
        );
    }

    #[test]
    fn empty_annotations_is_default() {
        assert_eq!(
            RouteConfig::from_annotations(&BTreeMap::new()),
            RouteConfig::default()
        );
    }
}
