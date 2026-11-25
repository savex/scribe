//! Windows: the IP Helper tables with the owning pid (`GetExtendedTcpTable` with
//! `TCP_TABLE_OWNER_PID_ALL`, `GetExtendedUdpTable` with `UDP_TABLE_OWNER_PID`, IPv4 and IPv6),
//! paths from `QueryFullProcessImageNameW`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCP_STATE_LISTEN, MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::{SocketEntry, SocketTable, Transport};

pub struct IpHelperTable;

/// A port in network byte order in the low 16 bits.
fn port(p: u32) -> u16 {
    u16::from_be((p & 0xffff) as u16)
}

/// Call a table function until the buffer is big enough; returns the rows after the count.
fn table<T: Copy>(get: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> io::Result<Vec<T>> {
    let mut size = 0u32;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..8 {
        let rc = get(buf.as_mut_ptr().cast(), &mut size);
        if rc == NO_ERROR {
            let base = buf.as_ptr().cast::<u8>();
            // SAFETY: the table starts with a u32 count, then the rows (aligned like `T`).
            let count = unsafe { base.cast::<u32>().read_unaligned() } as usize;
            let offset = std::mem::align_of::<T>().max(4);
            let mut rows = Vec::with_capacity(count);
            for i in 0..count {
                // SAFETY: the API wrote `count` rows after the count field.
                let row = unsafe {
                    base.add(offset + i * std::mem::size_of::<T>())
                        .cast::<T>()
                        .read_unaligned()
                };
                rows.push(row);
            }
            return Ok(rows);
        }
        if rc != ERROR_INSUFFICIENT_BUFFER {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        // Room for a few new sockets between the two calls.
        buf = vec![0u64; (size as usize + 4096) / 8 + 1];
        size = (buf.len() * 8) as u32;
    }
    Err(io::Error::other("the socket table kept growing"))
}

impl SocketTable for IpHelperTable {
    fn snapshot(&mut self) -> io::Result<Vec<SocketEntry>> {
        let mut entries = Vec::new();
        // SAFETY (all four): the buffer and size come from `table`, which sizes them as asked.
        let tcp4: Vec<MIB_TCPROW_OWNER_PID> = table(|b, s| unsafe {
            GetExtendedTcpTable(b, s, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
        })?;
        for r in tcp4 {
            if r.dwState as i32 == MIB_TCP_STATE_LISTEN {
                continue;
            }
            entries.push(SocketEntry {
                transport: Transport::Tcp,
                local: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
                    port(r.dwLocalPort),
                ),
                remote: Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes())),
                    port(r.dwRemotePort),
                )),
                pid: r.dwOwningPid,
            });
        }
        let tcp6: Vec<MIB_TCP6ROW_OWNER_PID> = table(|b, s| unsafe {
            GetExtendedTcpTable(b, s, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
        })?;
        for r in tcp6 {
            if r.dwState as i32 == MIB_TCP_STATE_LISTEN {
                continue;
            }
            entries.push(SocketEntry {
                transport: Transport::Tcp,
                local: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                    port(r.dwLocalPort),
                ),
                remote: Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),
                    port(r.dwRemotePort),
                )),
                pid: r.dwOwningPid,
            });
        }
        let udp4: Vec<MIB_UDPROW_OWNER_PID> = table(|b, s| unsafe {
            GetExtendedUdpTable(b, s, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
        })?;
        for r in udp4 {
            entries.push(SocketEntry {
                transport: Transport::Udp,
                local: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
                    port(r.dwLocalPort),
                ),
                remote: None,
                pid: r.dwOwningPid,
            });
        }
        let udp6: Vec<MIB_UDP6ROW_OWNER_PID> = table(|b, s| unsafe {
            GetExtendedUdpTable(b, s, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
        })?;
        for r in udp6 {
            entries.push(SocketEntry {
                transport: Transport::Udp,
                local: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                    port(r.dwLocalPort),
                ),
                remote: None,
                pid: r.dwOwningPid,
            });
        }
        Ok(entries)
    }

    fn process_path(&self, pid: u32) -> Option<String> {
        // SAFETY: plain handle use; the handle is closed below.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` UTF-16 units.
        let ok = unsafe {
            QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
        };
        // SAFETY: opened above.
        unsafe { CloseHandle(handle) };
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}
