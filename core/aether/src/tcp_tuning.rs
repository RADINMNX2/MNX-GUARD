//! Egress TCP tuning for the sockets the core itself opens.
//!
//! Android gives no way to change another app's congestion control or Nagle
//! policy without root, and replacing the kernel's TCP fast path with a
//! userspace stack would cost more throughput than it returns. What is left —
//! and what actually moves the needle on a lossy mobile link — is per-socket
//! tuning of the connections the core carries:
//!
//!   * `TCP_NODELAY` so small writes (a request line, an ACK-sized payload) are
//!     not held back by Nagle against the previous segment's ACK.
//!   * keepalives with a short idle so an idle carrier NAT mapping is kept
//!     alive rather than silently dropped, which is a common mid-session stall.
//!   * `TCP_USER_TIMEOUT` so a black-holed path fails the connection instead of
//!     hanging it for the kernel default of ~15 minutes.
//!   * widened `SO_SNDBUF`/`SO_RCVBUF` so a high bandwidth-delay path is not
//!     throttled by the ~64 KiB default window.
//!
//! Every option is best-effort: a kernel that rejects one never fails the
//! connection over it. `AETHER_TCP_TUNING=off` disables the whole module.

use std::io;

/// A socket the tuning can be applied to. Implemented for both the blocking and
/// the async `TcpStream`, which are the only two the core ever egresses on.
pub trait EgressStream {
    fn disable_nagle(&self) -> io::Result<()>;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn raw_fd(&self) -> std::os::fd::RawFd;
}

impl EgressStream for std::net::TcpStream {
    fn disable_nagle(&self) -> io::Result<()> {
        self.set_nodelay(true)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(self)
    }
}

impl EgressStream for tokio::net::TcpStream {
    fn disable_nagle(&self) -> io::Result<()> {
        self.set_nodelay(true)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(self)
    }
}

/// Applies the tuned options to [stream] and returns how many the kernel
/// accepted. Callers treat the count as diagnostic only.
pub fn apply<S: EgressStream>(stream: &S) -> usize {
    if !crate::sysprofile::tcp_tuning_enabled() {
        return 0;
    }
    let mut applied = 0usize;
    if stream.disable_nagle().is_ok() {
        applied += 1;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        applied += linux::apply(stream.raw_fd());
    }
    applied
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::os::fd::RawFd;

    fn set_int(fd: RawFd, level: libc::c_int, option: libc::c_int, value: libc::c_int) -> bool {
        let size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        unsafe {
            libc::setsockopt(
                fd,
                level,
                option,
                &value as *const libc::c_int as *const libc::c_void,
                size,
            ) == 0
        }
    }

    pub(super) fn apply(fd: RawFd) -> usize {
        let mut applied = 0usize;

        if set_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1) {
            applied += 1;
        }
        if set_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, 30) {
            applied += 1;
        }
        if set_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, 10) {
            applied += 1;
        }
        if set_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 3) {
            applied += 1;
        }
        if set_int(fd, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, 30_000) {
            applied += 1;
        }

        let recv = crate::sysprofile::tcp_egress_recv_buf_bytes();
        let send = crate::sysprofile::tcp_egress_send_buf_bytes();
        if recv <= i32::MAX as usize
            && set_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, recv as libc::c_int)
        {
            applied += 1;
        }
        if send <= i32::MAX as usize
            && set_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, send as libc::c_int)
        {
            applied += 1;
        }
        applied
    }
}
