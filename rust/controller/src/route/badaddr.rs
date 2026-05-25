use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a dialed address stays "bad" after a failure. Port of `badDuration`.
const BAD_DURATION: Duration = Duration::from_secs(2);

/// Tracks recently-failed addresses so the load balancer can skip them.
/// Port of `route/badaddr.go`. Keyed by host (port stripped).
#[derive(Default)]
pub struct BadAddrs {
    addrs: Mutex<HashMap<String, Instant>>,
}

impl BadAddrs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark an address bad. Accepts `host` or `host:port`; the port is stripped.
    pub fn mark_bad(&self, addr: &str) {
        let host = host_of(addr);
        // Returns whether this is a transition into bad (used for once-per-outage
        // logging in the Go version); logging is wired up at a later phase.
        let _transitioned = self.mark(host);
    }

    /// Records `host` as bad and reports whether it transitioned from not-bad.
    pub fn mark(&self, host: &str) -> bool {
        let transitioned = !self.is_bad(host);
        self.addrs
            .lock()
            .unwrap()
            .insert(host.to_string(), Instant::now());
        transitioned
    }

    pub fn is_bad(&self, host: &str) -> bool {
        match self.addrs.lock().unwrap().get(host) {
            Some(t) => t.elapsed() <= BAD_DURATION,
            None => false,
        }
    }

    /// Convenience for callers holding an `Option<&BadAddrs>` (a nil table in Go
    /// reports nothing bad).
    pub fn is_bad_opt(bad: Option<&BadAddrs>, host: &str) -> bool {
        bad.is_some_and(|b| b.is_bad(host))
    }

    /// Drop entries whose bad window has expired.
    pub fn clear(&self) {
        self.addrs
            .lock()
            .unwrap()
            .retain(|_, t| t.elapsed() <= BAD_DURATION);
    }

    #[cfg(test)]
    fn store_at(&self, host: &str, at: Instant) {
        self.addrs.lock().unwrap().insert(host.to_string(), at);
    }

    #[cfg(test)]
    fn contains(&self, host: &str) -> bool {
        self.addrs.lock().unwrap().contains_key(host)
    }
}

/// Strip a `:port` suffix, mirroring how Go's `net.SplitHostPort` is used:
/// a bare host with no port (parse failure) keeps the whole string.
fn host_of(addr: &str) -> &str {
    if addr.starts_with('[') {
        // [ipv6]:port or bare [ipv6]
        if let Some(end) = addr.find(']') {
            return &addr[1..end];
        }
        return addr;
    }
    // exactly one ':' => host:port; zero or many (bare IPv6) => use whole
    if addr.matches(':').count() == 1 {
        if let Some((host, _port)) = addr.split_once(':') {
            return host;
        }
    }
    addr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_and_is_bad() {
        let bad = BadAddrs::new();
        bad.mark_bad("192.168.0.10:8080");
        assert!(bad.is_bad("192.168.0.10"));
        // clear without expiry: still bad
        bad.clear();
        assert!(bad.is_bad("192.168.0.10"));

        // mark bad without port
        bad.mark_bad("192.168.0.11");
        assert!(bad.is_bad("192.168.0.11"));

        assert!(!bad.is_bad("192.168.0.1"));
    }

    #[test]
    fn expiry() {
        let bad = BadAddrs::new();
        let past = Instant::now()
            .checked_sub(2 * BAD_DURATION)
            .expect("instant in range");
        bad.store_at("192.168.0.20", past);
        assert!(!bad.is_bad("192.168.0.20"));

        bad.store_at("192.168.0.21", Instant::now());
        assert!(bad.is_bad("192.168.0.21"));
    }

    #[test]
    fn clear_removes_only_expired() {
        let bad = BadAddrs::new();
        let past = Instant::now().checked_sub(2 * BAD_DURATION).unwrap();
        bad.store_at("expired", past);
        bad.store_at("fresh", Instant::now());

        bad.clear();

        assert!(!bad.contains("expired"), "expired entry should be removed");
        assert!(bad.contains("fresh"), "fresh entry should be kept");
    }

    #[test]
    fn mark_transition() {
        let bad = BadAddrs::new();
        assert!(bad.mark("10.0.0.1"), "first mark is a transition");
        assert!(
            !bad.mark("10.0.0.1"),
            "already-bad host is not a transition"
        );

        let past = Instant::now().checked_sub(2 * BAD_DURATION).unwrap();
        bad.store_at("10.0.0.1", past);
        assert!(bad.mark("10.0.0.1"), "re-mark after expiry is a transition");
    }
}
