//! Per-route fixed-window rate limiting (annotations ratelimit-s/m/h). Port of
//! parapet's FixedWindowPerSecond/Minute/Hour. A single process-wide registry,
//! keyed by (route pattern, window), survives reloads (counts continue across
//! reloads rather than resetting — a minor, benign divergence from Go).

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub struct FixedWindows {
    map: Mutex<HashMap<(String, u8), Window>>,
}

struct Window {
    start: Instant,
    count: u32,
}

impl FixedWindows {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Record a hit for `key` in window `id` (0=s, 1=m, 2=h). Returns `true` if
    /// within `limit` for the current `period`, `false` if the limit is exceeded.
    pub fn allow(&self, key: &str, id: u8, limit: u32, period: Duration) -> bool {
        let mut map = self.map.lock().unwrap();
        let w = map.entry((key.to_string(), id)).or_insert(Window {
            start: Instant::now(),
            count: 0,
        });
        if w.start.elapsed() >= period {
            w.start = Instant::now();
            w.count = 0;
        }
        if w.count >= limit {
            return false;
        }
        w.count += 1;
        true
    }

    /// Drop windows whose route pattern is no longer served. Called on reload so
    /// the map tracks the live pattern set instead of accumulating an entry for
    /// every pattern ever configured (stale entries from deleted routes linger
    /// otherwise).
    pub fn retain_patterns(&self, patterns: &HashSet<&str>) {
        self.map
            .lock()
            .unwrap()
            .retain(|(pattern, _id), _| patterns.contains(pattern.as_str()));
    }
}

pub fn windows() -> &'static FixedWindows {
    static W: OnceLock<FixedWindows> = OnceLock::new();
    W.get_or_init(FixedWindows::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window_caps_then_resets() {
        let fw = FixedWindows::new();
        let p = Duration::from_millis(100);
        assert!(fw.allow("r", 0, 2, p));
        assert!(fw.allow("r", 0, 2, p));
        assert!(!fw.allow("r", 0, 2, p)); // 3rd in window: rejected
                                          // different key independent
        assert!(fw.allow("other", 0, 2, p));
        std::thread::sleep(Duration::from_millis(120));
        assert!(fw.allow("r", 0, 2, p)); // window elapsed -> allowed again
    }

    #[test]
    fn retain_patterns_drops_stale_routes() {
        let fw = FixedWindows::new();
        let p = Duration::from_secs(60);
        fw.allow("keep/path", 0, 10, p);
        fw.allow("keep/path", 1, 10, p); // same pattern, different window id
        fw.allow("gone/path", 0, 10, p);
        assert_eq!(fw.map.lock().unwrap().len(), 3);

        let live: HashSet<&str> = ["keep/path"].into_iter().collect();
        fw.retain_patterns(&live);

        let map = fw.map.lock().unwrap();
        assert_eq!(map.len(), 2, "both windows of the live pattern kept");
        assert!(map.contains_key(&("keep/path".to_string(), 0)));
        assert!(map.contains_key(&("keep/path".to_string(), 1)));
        assert!(!map.contains_key(&("gone/path".to_string(), 0)));
    }

    #[test]
    fn windows_are_independent_per_id() {
        // the same route is counted separately for s/m/h (ids 0/1/2), so
        // exhausting the per-second window must not affect the per-minute one.
        let fw = FixedWindows::new();
        let p = Duration::from_secs(60);
        assert!(fw.allow("r", 0, 1, p));
        assert!(!fw.allow("r", 0, 1, p)); // id 0 exhausted
        assert!(fw.allow("r", 1, 1, p)); // id 1 independent -> still allowed
        assert!(fw.allow("r", 2, 1, p)); // id 2 independent -> still allowed
    }
}
