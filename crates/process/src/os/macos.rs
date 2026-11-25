//! macOS: every process's socket descriptors through `libproc` (`proc_listallpids`,
//! `PROC_PIDLISTFDS`, `PROC_PIDFDSOCKETINFO`), paths from `proc_pidpath`.
//!
//! `libc` has the functions but not `struct socket_fdinfo`, so the few fields needed are read
//! at their offsets from `<sys/proc_info.h>` (the same on arm64 and x86_64, checked with
//! `offsetof` against the SDK); the live test finds this process's own sockets through them.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{SocketEntry, SocketTable, Transport};

pub struct LibprocTable;

/// `sizeof(struct socket_fdinfo)`.
const SOCKET_FDINFO: usize = 792;
/// Offsets in `struct socket_fdinfo`.
const SOI_PROTOCOL: usize = 180;
const SOI_KIND: usize = 256;
const INSI_FPORT: usize = 264;
const INSI_LPORT: usize = 268;
const INSI_VFLAG: usize = 288;
const INSI_FADDR: usize = 296;
const INSI_LADDR: usize = 312;
const TCPSI_STATE: usize = 344;
const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;
const INI_IPV4: u8 = 1;
const INI_IPV6: u8 = 2;
const TSI_S_LISTEN: i32 = 1;

fn i32_at(buf: &[u8], at: usize) -> i32 {
    i32::from_ne_bytes(buf[at..at + 4].try_into().unwrap())
}

/// A port stored as `int` in network byte order.
fn port_at(buf: &[u8], at: usize) -> u16 {
    u16::from_be((i32_at(buf, at) as u32 & 0xffff) as u16)
}

/// `union { struct in4in6_addr; struct in6_addr; }`: IPv4 sits in the last four bytes.
fn addr_at(buf: &[u8], at: usize, v4: bool) -> IpAddr {
    let bytes: [u8; 16] = buf[at..at + 16].try_into().unwrap();
    if v4 {
        IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
    } else {
        IpAddr::V6(Ipv6Addr::from(bytes))
    }
}

fn pids() -> io::Result<Vec<libc::pid_t>> {
    // SAFETY: a null buffer asks for the count.
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pids = vec![0 as libc::pid_t; count as usize + 64];
    let bytes = (pids.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
    // SAFETY: the buffer holds `bytes` bytes.
    let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    pids.truncate(n as usize);
    Ok(pids)
}

fn fds(pid: libc::pid_t) -> Vec<libc::proc_fdinfo> {
    // SAFETY: a null buffer asks for the size.
    let size =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if size <= 0 {
        return Vec::new();
    }
    let room = size as usize / std::mem::size_of::<libc::proc_fdinfo>() + 16;
    let mut list = vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0
        };
        room
    ];
    let bytes = (room * std::mem::size_of::<libc::proc_fdinfo>()) as libc::c_int;
    // SAFETY: the buffer holds `bytes` bytes.
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            list.as_mut_ptr().cast(),
            bytes,
        )
    };
    if got <= 0 {
        return Vec::new();
    }
    list.truncate(got as usize / std::mem::size_of::<libc::proc_fdinfo>());
    list
}

fn socket(pid: libc::pid_t, fd: i32) -> Option<SocketEntry> {
    let mut buf = vec![0u8; SOCKET_FDINFO];
    // SAFETY: the buffer is `socket_fdinfo`-sized.
    let got = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            buf.as_mut_ptr().cast(),
            SOCKET_FDINFO as libc::c_int,
        )
    };
    if got as usize != SOCKET_FDINFO {
        return None;
    }
    let kind = i32_at(&buf, SOI_KIND);
    if kind != SOCKINFO_IN && kind != SOCKINFO_TCP {
        return None;
    }
    let transport = match i32_at(&buf, SOI_PROTOCOL) {
        libc::IPPROTO_TCP => Transport::Tcp,
        libc::IPPROTO_UDP => Transport::Udp,
        _ => return None,
    };
    if kind == SOCKINFO_TCP && i32_at(&buf, TCPSI_STATE) == TSI_S_LISTEN {
        return None;
    }
    let v4 = match buf[INSI_VFLAG] {
        f if f & INI_IPV4 != 0 => true,
        f if f & INI_IPV6 != 0 => false,
        _ => return None,
    };
    let local = SocketAddr::new(addr_at(&buf, INSI_LADDR, v4), port_at(&buf, INSI_LPORT));
    let fport = port_at(&buf, INSI_FPORT);
    let remote = (fport != 0).then(|| SocketAddr::new(addr_at(&buf, INSI_FADDR, v4), fport));
    Some(SocketEntry {
        transport,
        local,
        remote,
        pid: pid as u32,
    })
}

impl SocketTable for LibprocTable {
    fn snapshot(&mut self) -> io::Result<Vec<SocketEntry>> {
        let mut entries = Vec::new();
        for pid in pids()? {
            for fd in fds(pid) {
                if fd.proc_fdtype as libc::c_int == libc::PROX_FDTYPE_SOCKET {
                    entries.extend(socket(pid, fd.proc_fd));
                }
            }
        }
        Ok(entries)
    }

    fn process_path(&self, pid: u32) -> Option<String> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: the buffer holds PROC_PIDPATHINFO_MAXSIZE bytes.
        let n = unsafe {
            libc::proc_pidpath(
                pid as libc::c_int,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
            )
        };
        (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
    }
}
