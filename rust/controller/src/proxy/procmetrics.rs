//! Process-level metrics matching Go's `client_golang` process collector.
//!
//! Why custom instead of the `prometheus` crate's `ProcessCollector`: that one
//! computes `process_cpu_seconds_total` with **integer** division by `CLK_TCK`
//! (`(utime + stime) / CLK_TCK` as u64), truncating to whole CPU-seconds — so a
//! lightly-loaded process reads 0 and `rate()` is jumpy. Go divides as a float;
//! this collector does too, for sub-second (ms) precision. It also exposes the
//! three extras the crate lacks: `process_virtual_memory_max_bytes` and
//! `process_network_{receive,transmit}_bytes_total`.
//!
//! The metric values come from `/proc`, so they only populate on Linux; `start()`
//! is gated to Linux in `main()`. The module itself compiles everywhere (only
//! `std` + `libc::sysconf`), and the `/proc` parsers are pure functions covered
//! by unit tests so the tricky parsing is verified off-Linux too.

use std::fs;
use std::sync::OnceLock;
use std::time::Duration;

use prometheus::{register_counter, register_gauge, Counter, Gauge};

struct ProcMetrics {
    cpu: Counter,
    open_fds: Gauge,
    max_fds: Gauge,
    vsize: Gauge,
    vsize_max: Gauge,
    rss: Gauge,
    start_time: Gauge,
    net_rx: Counter,
    net_tx: Counter,
}

fn metrics() -> &'static ProcMetrics {
    static M: OnceLock<ProcMetrics> = OnceLock::new();
    M.get_or_init(|| ProcMetrics {
        cpu: register_counter!(
            "process_cpu_seconds_total",
            "Total user and system CPU time spent in seconds"
        )
        .expect("register process_cpu_seconds_total"),
        open_fds: register_gauge!("process_open_fds", "Number of open file descriptors")
            .expect("register process_open_fds"),
        max_fds: register_gauge!("process_max_fds", "Maximum number of open file descriptors")
            .expect("register process_max_fds"),
        vsize: register_gauge!(
            "process_virtual_memory_bytes",
            "Virtual memory size in bytes"
        )
        .expect("register process_virtual_memory_bytes"),
        vsize_max: register_gauge!(
            "process_virtual_memory_max_bytes",
            "Maximum amount of virtual memory available in bytes"
        )
        .expect("register process_virtual_memory_max_bytes"),
        rss: register_gauge!(
            "process_resident_memory_bytes",
            "Resident memory size in bytes"
        )
        .expect("register process_resident_memory_bytes"),
        start_time: register_gauge!(
            "process_start_time_seconds",
            "Start time of the process since unix epoch in seconds"
        )
        .expect("register process_start_time_seconds"),
        net_rx: register_counter!(
            "process_network_receive_bytes_total",
            "Number of bytes received by the process over the network"
        )
        .expect("register process_network_receive_bytes_total"),
        net_tx: register_counter!(
            "process_network_transmit_bytes_total",
            "Number of bytes sent by the process over the network"
        )
        .expect("register process_network_transmit_bytes_total"),
    })
}

/// Register the process metrics and start a 5s background refresher. Linux-only
/// at runtime (reads `/proc`); call once at startup.
pub fn start() {
    let m = metrics();
    if let Some(t) = read_start_time_secs() {
        m.start_time.set(t);
    }
    std::thread::spawn(|| loop {
        refresh(metrics());
        std::thread::sleep(Duration::from_secs(5));
    });
}

fn refresh(m: &ProcMetrics) {
    if let Ok(s) = fs::read_to_string("/proc/self/stat") {
        if let Some(st) = parse_stat(&s) {
            // FLOAT division (the fix): sub-second CPU is preserved.
            let secs = (st.utime + st.stime) as f64 / clk_tck();
            let cur = m.cpu.get();
            if secs > cur {
                m.cpu.inc_by(secs - cur);
            }
            m.vsize.set(st.vsize as f64);
            m.rss.set(st.rss_pages as f64 * page_size());
        }
    }
    if let Ok(rd) = fs::read_dir("/proc/self/fd") {
        m.open_fds.set(rd.count() as f64);
    }
    if let Ok(s) = fs::read_to_string("/proc/self/limits") {
        if let Some((nofile, as_max)) = parse_limits(&s) {
            m.max_fds.set(nofile);
            m.vsize_max.set(as_max);
        }
    }
    if let Ok(s) = fs::read_to_string("/proc/self/net/dev") {
        if let Some((rx, tx)) = parse_net_dev(&s) {
            inc_counter_to(&m.net_rx, rx);
            inc_counter_to(&m.net_tx, tx);
        }
    }
}

/// Move a monotonic counter up to `target` (the `/proc` values are absolute).
fn inc_counter_to(c: &Counter, target: f64) {
    let cur = c.get();
    if target > cur {
        c.inc_by(target - cur);
    }
}

fn read_start_time_secs() -> Option<f64> {
    let st = parse_stat(&fs::read_to_string("/proc/self/stat").ok()?)?;
    let btime = parse_btime(&fs::read_to_string("/proc/stat").ok()?)?;
    Some(btime as f64 + st.starttime as f64 / clk_tck())
}

struct Stat {
    utime: u64,
    stime: u64,
    starttime: u64,
    vsize: u64,
    rss_pages: u64,
}

/// Parse `/proc/self/stat`. Field 2 (comm) is parenthesized and may contain
/// spaces and `)`, so fields are taken after the LAST `)` — everything past it
/// is space-separated starting at field 3.
fn parse_stat(content: &str) -> Option<Stat> {
    let rparen = content.rfind(')')?;
    let f: Vec<&str> = content.get(rparen + 1..)?.split_whitespace().collect();
    // f[0] == field 3 (state); field N -> f[N - 3].
    let get = |n: usize| -> Option<u64> { f.get(n - 3)?.parse().ok() };
    Some(Stat {
        utime: get(14)?,
        stime: get(15)?,
        starttime: get(22)?,
        vsize: get(23)?,
        rss_pages: get(24)?,
    })
}

fn parse_btime(content: &str) -> Option<u64> {
    content
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse().ok())
}

/// Soft limits for `Max open files` (RLIMIT_NOFILE) and `Max address space`
/// (RLIMIT_AS). `unlimited` maps to `-1`, matching client_golang.
fn parse_limits(content: &str) -> Option<(f64, f64)> {
    let mut nofile = None;
    let mut as_max = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Max open files") {
            nofile = parse_limit_value(rest);
        } else if let Some(rest) = line.strip_prefix("Max address space") {
            as_max = parse_limit_value(rest);
        }
    }
    Some((nofile?, as_max?))
}

fn parse_limit_value(rest: &str) -> Option<f64> {
    match rest.split_whitespace().next()? {
        "unlimited" => Some(-1.0),
        v => v.parse().ok(),
    }
}

/// Sum the Receive and Transmit byte columns across all interfaces in
/// `/proc/self/net/dev` (Receive bytes = col 0, Transmit bytes = col 8 after the
/// `iface:` prefix).
fn parse_net_dev(content: &str) -> Option<(f64, f64)> {
    let mut rx = 0.0;
    let mut tx = 0.0;
    for line in content.lines() {
        let Some((_iface, stats)) = line.split_once(':') else {
            continue; // the two header lines have no ':'
        };
        let cols: Vec<&str> = stats.split_whitespace().collect();
        if let (Some(r), Some(t)) = (cols.first(), cols.get(8)) {
            rx += r.parse::<f64>().unwrap_or(0.0);
            tx += t.parse::<f64>().unwrap_or(0.0);
        }
    }
    Some((rx, tx))
}

fn clk_tck() -> f64 {
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 {
        v as f64
    } else {
        100.0
    }
}

fn page_size() -> f64 {
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 {
        v as f64
    } else {
        4096.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parses_fields_after_comm() {
        // utime=250 stime=130 (=> 380 ticks => 3.8s at CLK_TCK=100, NOT 3)
        // starttime=99999 vsize=789000000 rss=1500 pages
        let s = "1234 (parapet-ingress) S 1 1234 1234 0 -1 4194560 1000 0 0 0 \
                 250 130 0 0 20 0 8 0 99999 789000000 1500 0 0";
        let st = parse_stat(s).unwrap();
        assert_eq!(st.utime, 250);
        assert_eq!(st.stime, 130);
        assert_eq!(st.starttime, 99999);
        assert_eq!(st.vsize, 789_000_000);
        assert_eq!(st.rss_pages, 1500);
        // the fix: fractional seconds, not truncated to 3
        assert_eq!((st.utime + st.stime) as f64 / 100.0, 3.8);
    }

    #[test]
    fn stat_handles_comm_with_spaces_and_parens() {
        // comm itself contains a space and a ')'
        let s = "9 (we (ir)d) R 1 9 9 0 -1 0 0 0 0 0 \
                 7 3 0 0 20 0 1 0 4242 555 9 0";
        let st = parse_stat(s).unwrap();
        assert_eq!(st.utime, 7);
        assert_eq!(st.stime, 3);
        assert_eq!(st.starttime, 4242);
        assert_eq!(st.vsize, 555);
        assert_eq!(st.rss_pages, 9);
    }

    #[test]
    fn limits_parses_soft_and_unlimited() {
        let s = "Limit                     Soft Limit           Hard Limit           Units\n\
                 Max open files            1024                 524288               files\n\
                 Max address space         unlimited            unlimited            bytes\n";
        let (nofile, as_max) = parse_limits(s).unwrap();
        assert_eq!(nofile, 1024.0);
        assert_eq!(as_max, -1.0);
    }

    #[test]
    fn net_dev_sums_interfaces() {
        let s = "Inter-|   Receive                                                |  Transmit\n \
                 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    \
                 lo:    1000      10    0    0    0     0          0         0     2000      10    0    0    0     0       0          0\n  \
                 eth0:  500000     400    0    0    0     0          0         0   250000     300    0    0    0     0       0          0\n";
        let (rx, tx) = parse_net_dev(s).unwrap();
        assert_eq!(rx, 501_000.0); // 1000 + 500000
        assert_eq!(tx, 252_000.0); // 2000 + 250000
    }

    #[test]
    fn btime_parsed() {
        let s = "cpu  1 2 3\nbtime 1700000000\nprocesses 99\n";
        assert_eq!(parse_btime(s), Some(1_700_000_000));
    }
}
