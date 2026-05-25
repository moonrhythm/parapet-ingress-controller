use std::sync::atomic::{AtomicU32, Ordering};

use super::badaddr::BadAddrs;

/// Round-robin load balancer over a fixed (immutable) list of pod IPs.
///
/// Port of `route/rrlb.go`. The counter is **pre-incremented** before taking
/// the modulo (Go's `atomic.AddUint32` returns the new value), so for a 3-IP
/// set the first `get` returns index 1, not 0 — the tests depend on this.
pub struct Rrlb {
    ips: Vec<String>,
    current: AtomicU32,
}

impl Rrlb {
    pub fn new(ips: Vec<String>) -> Self {
        Self {
            ips,
            current: AtomicU32::new(0),
        }
    }

    pub fn ips(&self) -> &[String] {
        &self.ips
    }

    /// Returns the next non-bad IP, or `""` if the set is empty or all bad.
    /// `bad` may be `None` (treated as "nothing is bad").
    pub fn get(&self, bad: Option<&BadAddrs>) -> String {
        let l = self.ips.len();
        if l == 0 {
            return String::new();
        }
        if l == 1 {
            return self.ips[0].clone();
        }

        // pre-increment then modulo, matching Go's atomic.AddUint32 semantics
        let n = self.current.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let p = (n % l as u32) as usize;
        for k in 0..l {
            let i = (p + k) % l;
            let ip = &self.ips[i];
            if !BadAddrs::is_bad_opt(bad, ip) {
                return ip.clone();
            }
        }
        // all bad: return empty so requests fail fast instead of queueing
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let lb = Rrlb::new(vec![]);
        assert_eq!(lb.get(None), "");
        assert_eq!(lb.get(None), "");
        assert_eq!(lb.get(None), "");
    }

    #[test]
    fn single() {
        let lb = Rrlb::new(vec!["192.168.1.1".into()]);
        assert_eq!(lb.get(None), "192.168.1.1");
        assert_eq!(lb.get(None), "192.168.1.1");
        assert_eq!(lb.get(None), "192.168.1.1");
    }

    #[test]
    fn all_healthy() {
        let lb = Rrlb::new(vec![
            "192.168.1.1".into(),
            "192.168.1.2".into(),
            "192.168.1.3".into(),
        ]);
        assert_eq!(lb.get(None), "192.168.1.2");
        assert_eq!(lb.get(None), "192.168.1.3");
        assert_eq!(lb.get(None), "192.168.1.1");
        assert_eq!(lb.get(None), "192.168.1.2");
    }

    #[test]
    fn one_bad() {
        let lb = Rrlb::new(vec![
            "192.168.1.1".into(),
            "192.168.1.2".into(),
            "192.168.1.3".into(),
        ]);
        let bad = BadAddrs::new();
        bad.mark_bad("192.168.1.3");
        assert_eq!(lb.get(Some(&bad)), "192.168.1.2");
        assert_eq!(lb.get(Some(&bad)), "192.168.1.1"); // 3 is bad so 1 is returned
        assert_eq!(lb.get(Some(&bad)), "192.168.1.1"); // next of 3 is 1
        assert_eq!(lb.get(Some(&bad)), "192.168.1.2");
    }

    #[test]
    fn all_bad() {
        let lb = Rrlb::new(vec![
            "192.168.1.1".into(),
            "192.168.1.2".into(),
            "192.168.1.3".into(),
        ]);
        let bad = BadAddrs::new();
        bad.mark_bad("192.168.1.1");
        bad.mark_bad("192.168.1.2");
        bad.mark_bad("192.168.1.3");
        assert_eq!(lb.get(Some(&bad)), "");
        assert_eq!(lb.get(Some(&bad)), "");
        assert_eq!(lb.get(Some(&bad)), "");
        assert_eq!(lb.get(Some(&bad)), "");
    }
}
