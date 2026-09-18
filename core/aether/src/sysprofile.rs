use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    pub tier: Tier,
    pub cpus: usize,
    pub mem_mb: Option<u64>,
    pub scan_concurrency_cap: usize,
    pub udp_socket_buf: usize,
    pub netstack_tcp_rx_buf: usize,
    pub netstack_tcp_tx_buf: usize,
    pub netstack_udp_buf: usize,
    pub channel_capacity: usize,
    pub h2_stream_window: u32,
    pub h2_connection_window: u32,
    /// QUIC connection-level flow-control window, bytes (`set_initial_max_data`).
    pub quic_connection_window: u64,
    /// QUIC per-stream flow-control window, bytes.
    pub quic_stream_window: u64,
    /// Egress TCP receive buffer, bytes (`SO_RCVBUF`), also the ceiling on a
    /// download the core carries over TCP.
    pub tcp_egress_recv_buf: usize,
    /// Egress TCP send buffer, bytes (`SO_SNDBUF`).
    pub tcp_egress_send_buf: usize,
    /// Whether the egress TCP tuning module is active (`AETHER_TCP_TUNING`).
    pub tcp_tuning: bool,
}

static TUNING: OnceLock<Tuning> = OnceLock::new();

fn detected_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[cfg(target_os = "linux")]
fn total_mem_mb() -> Option<u64> {
    let data = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

#[cfg(target_os = "android")]
fn total_mem_mb() -> Option<u64> {
    let data = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn total_mem_mb() -> Option<u64> {
    let mut size: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    let name = b"hw.memsize\0";
    let ret = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            &mut size as *mut u64 as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret == 0 {
        Some(size / 1024 / 1024)
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
fn total_mem_mb() -> Option<u64> {
    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page_file: u64,
        avail_page_file: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalMemoryStatusEx(buf: *mut MemoryStatusEx) -> i32;
    }

    let mut status = MemoryStatusEx {
        length: std::mem::size_of::<MemoryStatusEx>() as u32,
        memory_load: 0,
        total_phys: 0,
        avail_phys: 0,
        total_page_file: 0,
        avail_page_file: 0,
        total_virtual: 0,
        avail_virtual: 0,
        avail_extended_virtual: 0,
    };

    let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
    if ok != 0 {
        Some(status.total_phys / 1024 / 1024)
    } else {
        None
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "windows"
)))]
fn total_mem_mb() -> Option<u64> {
    None
}

fn detect_tier(cpus: usize, mem_mb: Option<u64>) -> Tier {
    if let Ok(v) = std::env::var("AETHER_PERF_PROFILE") {
        match v.trim().to_lowercase().as_str() {
            "low" => return Tier::Low,
            "medium" | "mid" => return Tier::Medium,
            "high" => return Tier::High,
            _ => {}
        }
    }

    let mem_low = mem_mb.map(|m| m <= 384).unwrap_or(false);
    let mem_medium = mem_mb.map(|m| m <= 1536).unwrap_or(false);

    if cpus <= 2 || mem_low {
        Tier::Low
    } else if cpus <= 4 || mem_medium {
        Tier::Medium
    } else {
        Tier::High
    }
}

/// Reads a buffer size in bytes from the environment, ignoring anything
/// outside what a TCP socket can sensibly be given.
fn buffer_override(key: &str, fallback: usize) -> usize {
    std::env::var(key)
        .ok()
        .map(|value| buffer_value(&value, fallback))
        .unwrap_or(fallback)
}

/// Applies the [buffer_override] sanity bounds to a single parsed value.
fn buffer_value(value: &str, fallback: usize) -> usize {
    value
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|bytes| (16 * 1024..=64 * 1024 * 1024).contains(bytes))
        .unwrap_or(fallback)
}

/// Same contract as [buffer_override] but for a flow-control window in bytes.
fn window_override(key: &str, fallback: u64) -> u64 {
    std::env::var(key)
        .ok()
        .map(|value| window_value(&value, fallback))
        .unwrap_or(fallback)
}

fn window_value(value: &str, fallback: u64) -> u64 {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|bytes| (64 * 1024..=1024 * 1024 * 1024).contains(bytes))
        .unwrap_or(fallback)
}

/// Parses a YAML-style `on`/`off`/`0`/`1`/`true`/`false`/`yes`/`no` knob from
/// the environment, defaulting to [default] when unset or unrecognized.
fn env_flag(key: &str, default: bool) -> bool {
    std::env::var(key)
        .map(|value| flag_value(&value, default))
        .unwrap_or(default)
}

/// Applies the [env_flag] grammar to a single value.
fn flag_value(value: &str, default: bool) -> bool {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" | "0" | "false" | "no" => false,
        "on" | "1" | "true" | "yes" => true,
        _ => default,
    }
}

fn build_tuning() -> Tuning {
    let cpus = detected_cpus();
    let mem_mb = total_mem_mb();
    let tier = detect_tier(cpus, mem_mb);

    let (scan_concurrency_cap, udp_socket_buf, netstack_udp_buf, channel_capacity) = match tier {
        Tier::Low => (4usize, 256 * 1024, 32 * 1024, 128usize),
        Tier::Medium => (10usize, 2 * 1024 * 1024, 64 * 1024, 512usize),
        Tier::High => (usize::MAX, 7 * 1024 * 1024, 128 * 1024, 1024usize),
    };

    // smoltcp advertises whatever room is left in a socket's receive buffer as
    // that connection's TCP window, so this buffer is the second ceiling on a
    // download, again at window / round-trip-time. 256 KiB over a 110 ms round
    // trip is about 2.3 MB/s, which is what a tunnel settles at once the
    // carrier underneath it stops being the narrow part. Both halves are paid
    // for up front on every connection, so the receive side, which is where the
    // traffic is, gets the room and the send side stays modest.
    let (netstack_tcp_rx_buf, netstack_tcp_tx_buf) = match tier {
        Tier::Low => (256 * 1024, 128 * 1024),
        Tier::Medium => (1024 * 1024, 256 * 1024),
        Tier::High => (2 * 1024 * 1024, 512 * 1024),
    };

    let netstack_tcp_rx_buf = buffer_override("AETHER_NETSTACK_TCP_RX", netstack_tcp_rx_buf);
    let netstack_tcp_tx_buf = buffer_override("AETHER_NETSTACK_TCP_TX", netstack_tcp_tx_buf);

    // How much unacknowledged data the HTTP/2 edge may have on its way to us.
    // It is a promise rather than a reservation, but it does bound how much
    // arrives before we have drained it, so it follows the tier like the rest.
    // The ceiling it sets on a download is window / round-trip-time, which is
    // why the 64 KiB the h2 crate defaults to caps a 130 ms link at ~500 KB/s.
    let (h2_stream_window, h2_connection_window) = match tier {
        Tier::Low => (2 * 1024 * 1024, 4 * 1024 * 1024),
        Tier::Medium => (8 * 1024 * 1024, 16 * 1024 * 1024),
        Tier::High => (16 * 1024 * 1024, 32 * 1024 * 1024),
    };

    // QUIC flow control follows the same tier. These windows are the ceiling on
    // a single stream as window / round-trip-time, so the hardcoded 2 MB they
    // replace throttled BBR on a long-haul link: 2 MB over 200 ms is 10 MB/s no
    // matter how much bandwidth the path offers. Env overrides exist for A/B:
    // AETHER_QUIC_CONN_WINDOW / AETHER_QUIC_STREAM_WINDOW.
    let (quic_connection_window, quic_stream_window) = match tier {
        Tier::Low => (10_000_000u64, 2_000_000u64),
        Tier::Medium => (24_000_000u64, 8_000_000u64),
        Tier::High => (48_000_000u64, 16_000_000u64),
    };
    let quic_connection_window =
        window_override("AETHER_QUIC_CONN_WINDOW", quic_connection_window);
    let quic_stream_window = window_override("AETHER_QUIC_STREAM_WINDOW", quic_stream_window);

    // Egress TCP buffers follow the tier for the same reason as the QUIC
    // windows: window / round-trip-time is the ceiling on a single connection,
    // and the ~64 KiB kernel default caps a 150 ms path at well under 0.5 MB/s.
    let (tcp_egress_recv_buf, tcp_egress_send_buf) = match tier {
        Tier::Low => (256 * 1024usize, 128 * 1024usize),
        Tier::Medium => (512 * 1024usize, 256 * 1024usize),
        Tier::High => (1024 * 1024usize, 512 * 1024usize),
    };
    let tcp_egress_recv_buf = buffer_override("AETHER_TCP_RECV_BUF", tcp_egress_recv_buf);
    let tcp_egress_send_buf = buffer_override("AETHER_TCP_SEND_BUF", tcp_egress_send_buf);
    let tcp_tuning = env_flag("AETHER_TCP_TUNING", true);

    Tuning {
        tier,
        cpus,
        mem_mb,
        scan_concurrency_cap,
        udp_socket_buf,
        netstack_tcp_rx_buf,
        netstack_tcp_tx_buf,
        netstack_udp_buf,
        channel_capacity,
        h2_stream_window,
        h2_connection_window,
        quic_connection_window,
        quic_stream_window,
        tcp_egress_recv_buf,
        tcp_egress_send_buf,
        tcp_tuning,
    }
}

pub fn tuning() -> &'static Tuning {
    TUNING.get_or_init(build_tuning)
}

pub fn log_summary() {
    let t = tuning();
    let mem = t
        .mem_mb
        .map(|m| format!("{m}MB"))
        .unwrap_or_else(|| "unknown".to_string());
    let cap = if t.scan_concurrency_cap == usize::MAX {
        "unlimited".to_string()
    } else {
        t.scan_concurrency_cap.to_string()
    };
    log::info!(
        "[*] performance profile: {:?} (cpus={} mem={}); scan concurrency cap={}, udp socket buffer={}KB, netstack tcp buffers={}KB rx/{}KB tx, netstack udp buffer={}KB, channel capacity={}, h2 windows={}KB/{}KB",
        t.tier,
        t.cpus,
        mem,
        cap,
        t.udp_socket_buf / 1024,
        t.netstack_tcp_rx_buf / 1024,
        t.netstack_tcp_tx_buf / 1024,
        t.netstack_udp_buf / 1024,
        t.channel_capacity,
        t.h2_stream_window / 1024,
        t.h2_connection_window / 1024,
    );
    log::info!(
        "[*] egress TCP tuning: {} (buffers={}KB rx/{}KB tx)",
        if t.tcp_tuning { "on" } else { "off" },
        t.tcp_egress_recv_buf / 1024,
        t.tcp_egress_send_buf / 1024,
    );
}

pub fn cap_concurrency(requested: usize) -> usize {
    requested.min(tuning().scan_concurrency_cap)
}

pub fn udp_socket_buf_bytes() -> usize {
    tuning().udp_socket_buf
}

/// The receive buffer of a netstack TCP socket, which is also the window that
/// connection advertises, and so the ceiling on what it can pull down.
pub fn netstack_tcp_rx_buf_bytes() -> usize {
    tuning().netstack_tcp_rx_buf
}

pub fn netstack_tcp_tx_buf_bytes() -> usize {
    tuning().netstack_tcp_tx_buf
}

pub fn netstack_udp_buf_bytes() -> usize {
    tuning().netstack_udp_buf
}

pub fn channel_capacity() -> usize {
    tuning().channel_capacity
}

pub fn h2_stream_window_bytes() -> u32 {
    tuning().h2_stream_window
}

pub fn h2_connection_window_bytes() -> u32 {
    tuning().h2_connection_window
}

pub fn quic_connection_window_bytes() -> u64 {
    tuning().quic_connection_window
}

pub fn quic_stream_window_bytes() -> u64 {
    tuning().quic_stream_window
}

/// Egress TCP receive buffer for `SO_RCVBUF`, in bytes.
pub fn tcp_egress_recv_buf_bytes() -> usize {
    tuning().tcp_egress_recv_buf
}

/// Egress TCP send buffer for `SO_SNDBUF`, in bytes.
pub fn tcp_egress_send_buf_bytes() -> usize {
    tuning().tcp_egress_send_buf
}

/// Whether egress TCP tuning is enabled (`AETHER_TCP_TUNING`).
pub fn tcp_tuning_enabled() -> bool {
    tuning().tcp_tuning
}

#[cfg(test)]
mod tests {
    use super::{buffer_value, flag_value, window_value};

    #[test]
    fn flag_value_accepts_the_full_grammar_case_insensitively() {
        assert!(flag_value("on", true));
        assert!(flag_value("1", false));
        assert!(flag_value("YES", false));
        assert!(flag_value(" True ", false));
        assert!(!flag_value("off", true));
        assert!(!flag_value("0", true));
        assert!(!flag_value("no", true));
        assert!(!flag_value("FALSE", true));
    }

    #[test]
    fn flag_value_falls_back_on_garbage() {
        assert!(flag_value("maybe", true));
        assert!(!flag_value("maybe", false));
        assert!(flag_value("", true));
    }

    #[test]
    fn buffer_value_clamps_outside_the_socket_range() {
        let fallback = 128 * 1024usize;
        assert_eq!(buffer_value("65536", fallback), 65536);
        assert_eq!(buffer_value("4194304", fallback), 4 * 1024 * 1024);
        // Too small to be useful on any socket.
        assert_eq!(buffer_value("4096", fallback), fallback);
        // Beyond the 64 MiB sanity ceiling.
        assert_eq!(buffer_value("1073741824", fallback), fallback);
        // Not a number at all.
        assert_eq!(buffer_value("not a number", fallback), fallback);
        assert_eq!(buffer_value("", fallback), fallback);
    }

    #[test]
    fn window_value_clamps_outside_the_flow_control_range() {
        let fallback = 8 * 1024 * 1024u64;
        assert_eq!(window_value("16777216", fallback), 16 * 1024 * 1024);
        // Below the 64 KiB floor.
        assert_eq!(window_value("8192", fallback), fallback);
        // Above the 1 GiB ceiling.
        assert_eq!(window_value("4294967296", fallback), fallback);
        assert_eq!(window_value("junk", fallback), fallback);
    }
}
