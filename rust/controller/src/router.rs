//! A faithful reimplementation of the subset of Go's `http.ServeMux` matching
//! that this controller relies on: patterns are `host + path` strings where the
//! path is either *exact* (`/p`) or a *subtree* (`/p/`). Behavior verified
//! against the Go `TestBuildRoutes` / `TestMux` cases.
//!
//! Resolution order for a request `(host, path)`:
//!   1. host-specific match: exact, else longest registered subtree prefix
//!   2. host-less match (patterns registered without a host): same rule on path
//!   3. trailing-slash redirect: if `path` has no trailing slash but `path + "/"`
//!      is a registered subtree, redirect (Go returns 301 here)
//!   4. otherwise not found
//!
//! Host-specific patterns take precedence over host-less ones, matching Go.

use std::collections::HashMap;

#[derive(Debug, PartialEq)]
pub enum Match<'a, T> {
    /// A registered pattern matched; carries its value.
    Found(&'a T),
    /// Go would emit a 301 to this (trailing-slash) path.
    Redirect(String),
    NotFound,
}

pub struct Router<T> {
    // keyed by the full pattern: `host + path`, e.g. "example.com/api/".
    // host-less patterns are keyed by path alone, e.g. "/api/".
    map: HashMap<String, T>,
}

impl<T> Router<T> {
    pub fn new(map: HashMap<String, T>) -> Self {
        Self { map }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Registered pattern keys (`host + path`), for debug introspection.
    pub fn patterns(&self) -> Vec<&str> {
        self.map.keys().map(String::as_str).collect()
    }

    pub fn lookup(&self, host: &str, path: &str) -> Match<'_, T> {
        // Single pre-sized allocation for the combined `host + path` key. The
        // common (matched) path costs exactly this one String; the rare
        // redirect branch below reuses this same buffer instead of formatting
        // fresh keys.
        let mut full = String::with_capacity(host.len() + path.len() + 1);
        full.push_str(host);
        full.push_str(path);

        // 1. host-specific
        if let Some(v) = self.match_prefixed(&full) {
            return Match::Found(v);
        }
        // 2. host-less (keys are just the path)
        if let Some(v) = self.match_prefixed(path) {
            return Match::Found(v);
        }
        // 3. trailing-slash redirect. Reuse `full` for the "{full}/" probe (the
        // capacity above reserved the extra '/'), and slice it for "{path}/"
        // rather than allocating new keys.
        if !path.ends_with('/') {
            full.push('/');
            let host_slash_matches = self.map.contains_key(&full);
            // `full` is `host + path + "/"`; the `path + "/"` suffix is the
            // trailing `path.len() + 1` bytes — a borrow, no allocation.
            let path_slash = &full[host.len()..];
            if host_slash_matches || self.map.contains_key(path_slash) {
                return Match::Redirect(path_slash.to_string());
            }
        }
        // 4.
        Match::NotFound
    }

    /// Exact match on `s`, else the longest registered subtree key (one ending
    /// in `/`) that is a prefix of `s`.
    fn match_prefixed(&self, s: &str) -> Option<&T> {
        if let Some(v) = self.map.get(s) {
            return Some(v);
        }
        let bytes = s.as_bytes();
        // scan '/' positions right-to-left so the first hit is the longest prefix
        for idx in (0..s.len()).rev() {
            if bytes[idx] == b'/' {
                if let Some(v) = self.map.get(&s[..=idx]) {
                    return Some(v);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a router whose value for each pattern is the pattern itself.
    fn router(patterns: &[&str]) -> Router<String> {
        Router::new(
            patterns
                .iter()
                .map(|p| (p.to_string(), p.to_string()))
                .collect(),
        )
    }

    fn found<'a>(m: &'a Match<'a, String>) -> Option<&'a str> {
        match m {
            Match::Found(v) => Some(v.as_str()),
            _ => None,
        }
    }

    // Mirrors controller_test.go TestBuildRoutes.
    #[test]
    fn build_routes() {
        let r = router(&[
            "example.com/",
            "example.com/path",
            "example.com/path/",
            "example.com/path/path2",
        ]);
        let check = |path: &str, expected: &str| {
            assert_eq!(
                found(&r.lookup("example.com", path)),
                Some(expected),
                "path={path}"
            );
        };
        check("/", "example.com/");
        check("/path", "example.com/path");
        check("/path/test", "example.com/path/");
        check("/path/path2", "example.com/path/path2");
        check("/path/path2/path3", "example.com/path/");
    }

    // Mirrors controller_test.go TestMux.
    #[test]
    fn mux_prefix_host() {
        let r = router(&["example.com/"]);
        assert!(
            found(&r.lookup("example.com", "/")).is_some(),
            "match exact"
        );
        assert!(
            found(&r.lookup("example.com", "/test/path")).is_some(),
            "match prefix subtree"
        );
    }

    #[test]
    fn mux_prefix_path() {
        let r = router(&["example.com/path/"]);
        // "/path" (no trailing) does not invoke the handler; Go 301-redirects to "/path/"
        assert_eq!(
            r.lookup("example.com", "/path"),
            Match::Redirect("/path/".to_string())
        );
        // "/path/" matches exactly
        assert!(found(&r.lookup("example.com", "/path/")).is_some());
    }

    #[test]
    fn mux_exact_path() {
        let r = router(&["example.com/path"]);
        assert!(
            found(&r.lookup("example.com", "/path")).is_some(),
            "exact match"
        );
        // trailing slash on an exact pattern: no match, no redirect
        assert_eq!(r.lookup("example.com", "/path/"), Match::NotFound);
    }

    #[test]
    fn wrong_host_does_not_match() {
        let r = router(&["example.com/"]);
        assert_eq!(r.lookup("other.com", "/"), Match::NotFound);
    }

    #[test]
    fn host_less_pattern_matches_any_host_but_loses_to_host_specific() {
        let r = router(&["/shared/", "example.com/shared/"]);
        // host-less subtree matches an arbitrary host
        assert_eq!(
            found(&r.lookup("anything.com", "/shared/x")),
            Some("/shared/")
        );
        // host-specific wins for its own host
        assert_eq!(
            found(&r.lookup("example.com", "/shared/x")),
            Some("example.com/shared/")
        );
    }
}
