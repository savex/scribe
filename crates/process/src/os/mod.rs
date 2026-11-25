//! The socket table of each system. [`parse_proc_net`] is plain text parsing, so it is compiled
//! and tested everywhere; the readers compile only on their own system.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::SocketTable;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// The socket table of this system, or `None` where there is no reader.
pub fn os_table() -> Option<Box<dyn SocketTable>> {
    #[cfg(target_os = "linux")]
    return Some(Box::new(linux::ProcTable));
    #[cfg(target_os = "macos")]
    return Some(Box::new(macos::LibprocTable));
    #[cfg(windows)]
    return Some(Box::new(windows::IpHelperTable));
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    None
}

/// One line of `/proc/net/{tcp,tcp6,udp,udp6}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcNetEntry {
    pub local: SocketAddr,
    /// `None` when the remote address is all zeros (unconnected UDP, listening TCP).
    pub remote: Option<SocketAddr>,
    pub inode: u64,
    /// TCP state `0A` (LISTEN).
    pub listening: bool,
}

/// An address as the kernel prints it: 8 hex digits (IPv4) or 32 (IPv6), each 32-bit word in
/// the byte order of the machine (little-endian on every Linux target scribe builds for), then
/// `:` and the port in hex.
fn proc_addr(text: &str) -> Option<SocketAddr> {
    let (ip, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |s: &str| u32::from_str_radix(s, 16).ok().map(u32::to_le_bytes);
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(ip)?)),
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                bytes[4 * i..4 * i + 4].copy_from_slice(&word(&ip[8 * i..8 * i + 8])?);
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Parse the text of one `/proc/net` socket file; the header and unreadable lines are skipped.
pub fn parse_proc_net(text: &str) -> Vec<ProcNetEntry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let local = proc_addr(f[1])?;
            let remote = proc_addr(f[2])?;
            let remote = (!remote.ip().is_unspecified() || remote.port() != 0).then_some(remote);
            Some(ProcNetEntry {
                local,
                remote,
                inode: f[9].parse().ok()?,
                listening: f[3] == "0A",
            })
        })
        .collect()
}
