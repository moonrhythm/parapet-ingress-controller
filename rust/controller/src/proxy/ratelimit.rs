//! Per-route fixed-window rate limiting (annotations ratelimit-s/m/h). Port of
//! parapet's FixedWindowPerSecond/Minute/Hour. A single process-wide registry,
//! keyed by (route pattern, window), survives reloads (counts continue across
//! reloads rather than resetting — a minor, benign divergence from Go).

use std::collections::HashMap;
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
}
