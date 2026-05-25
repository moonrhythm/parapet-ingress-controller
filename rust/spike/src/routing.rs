// Port of the routing primitives we'll need: round-robin LB (route/rrlb.go) +
// bad-address skip/expiry (route/badaddr.go), behind an ArcSwap-able table.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    H1,
    H2c,
    Https,
}

/// Round-robin set of backend addresses, skipping ones currently marked bad.
pub struct Backend {
    pub addrs: Vec<String>,
    pub proto: Proto,
    cur: AtomicUsize,
}

impl Backend {
    pub fn new(addrs: Vec<String>, proto: Proto) -> Self {
        Self {
            addrs,
            proto,
            cur: AtomicUsize::new(0),
        }
    }

    /// Pick the next non-bad address, or None if every address is bad.
    pub fn pick(&self, bad: &BadAddrs) -> Option<String> {
        let l = self.addrs.len();
        if l == 0 {
            return None;
        }
        let start = self.cur.fetch_add(1, Ordering::Relaxed) % l;
        for k in 0..l {
            let a = &self.addrs[(start + k) % l];
            if !bad.is_bad(a) {
                return Some(a.clone());
            }
        }
        None
    }
}

pub type RouteTable = HashMap<String, Backend>;

/// Tracks addresses that recently failed to dial, with a short TTL (badaddr.go).
pub struct BadAddrs {
    inner: Mutex<HashMap<String, Instant>>,
    ttl: Duration,
}

impl BadAddrs {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(2),
        }
    }

    pub fn mark(&self, addr: &str) {
        self.inner
            .lock()
            .unwrap()
            .insert(addr.to_string(), Instant::now());
    }

    pub fn is_bad(&self, addr: &str) -> bool {
        match self.inner.lock().unwrap().get(addr) {
            Some(t) => t.elapsed() <= self.ttl,
            None => false,
        }
    }
}
