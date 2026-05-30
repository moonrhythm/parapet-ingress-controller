//! jemalloc internal allocator stats, exported as Prometheus gauges so unbounded
//! RSS growth can be diagnosed in Grafana instead of guessed at.
//!
//! The decisive pair is `jemalloc_allocated_bytes` (bytes the application has
//! malloc'd and not yet freed — the *live* heap) vs `jemalloc_resident_bytes`
//! (physically resident pages, ~RSS):
//!
//!   - `allocated` climbing monotonically  => a genuine **leak** (live memory
//!     that is never freed); no allocator can return it.
//!   - `allocated` flat while `resident`/`retained` climb => allocator
//!     **retention/fragmentation** (freed but not handed back); tune decay
//!     (`_RJEM_MALLOC_CONF=dirty_decay_ms:...`) rather than hunt a leak.
//!
//! Only meaningful when jemalloc is the global allocator (see `main.rs`), so this
//! is compiled out on msvc, where the system allocator is used.

#![cfg(not(target_env = "msvc"))]

use std::sync::OnceLock;
use std::time::Duration;

use prometheus::{register_int_gauge, IntGauge};
use tikv_jemalloc_ctl::{epoch, stats};

struct AllocMetrics {
    allocated: IntGauge,
    active: IntGauge,
    resident: IntGauge,
    retained: IntGauge,
    mapped: IntGauge,
}

fn metrics() -> &'static AllocMetrics {
    static M: OnceLock<AllocMetrics> = OnceLock::new();
    M.get_or_init(|| AllocMetrics {
        allocated: register_int_gauge!(
            "jemalloc_allocated_bytes",
            "Bytes allocated by the application and not yet freed (live heap)"
        )
        .expect("register jemalloc_allocated_bytes"),
        active: register_int_gauge!(
            "jemalloc_active_bytes",
            "Bytes in active pages used by the application"
        )
        .expect("register jemalloc_active_bytes"),
        resident: register_int_gauge!(
            "jemalloc_resident_bytes",
            "Bytes in physically resident data pages (approximates RSS)"
        )
        .expect("register jemalloc_resident_bytes"),
        retained: register_int_gauge!(
            "jemalloc_retained_bytes",
            "Bytes mapped but retained (not returned to the OS, virtual only)"
        )
        .expect("register jemalloc_retained_bytes"),
        mapped: register_int_gauge!(
            "jemalloc_mapped_bytes",
            "Bytes in active extents mapped by the allocator"
        )
        .expect("register jemalloc_mapped_bytes"),
    })
}

/// Register the jemalloc gauges and start a 5s background refresher (mirrors
/// `procmetrics::start`). Call once at startup, after the allocator is active.
pub fn start() {
    let m = metrics();
    std::thread::spawn(|| loop {
        refresh(metrics());
        std::thread::sleep(Duration::from_secs(5));
    });
    // prime once so the series exist immediately
    refresh(m);
}

fn refresh(m: &AllocMetrics) {
    // jemalloc's stats are cached and only recomputed when the epoch advances;
    // without this the gauges would never move. A failed advance/read just skips
    // this tick (the previous value stays).
    if epoch::advance().is_err() {
        return;
    }
    if let Ok(v) = stats::allocated::read() {
        m.allocated.set(v as i64);
    }
    if let Ok(v) = stats::active::read() {
        m.active.set(v as i64);
    }
    if let Ok(v) = stats::resident::read() {
        m.resident.set(v as i64);
    }
    if let Ok(v) = stats::retained::read() {
        m.retained.set(v as i64);
    }
    if let Ok(v) = stats::mapped::read() {
        m.mapped.set(v as i64);
    }
}
