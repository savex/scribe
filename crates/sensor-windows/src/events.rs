//! The ETW events the sensor reads, parsed from their user data field by field (no TDH, no
//! `unsafe`, any input), so the parsing is tested on every system.
//!
//! **Microsoft-Windows-Kernel-Network** (`{7DD42A49-5329-4832-8DFD-43D979153A88}`): one event per
//! TCP connection attempt and per UDP datagram sent, with the owning process. Every event starts
//! with the same fields; IPv4 and IPv6 differ in the address size:
//!
//! | Event | Meaning | Fields used |
//! |---|---|---|
//! | 12 / 28 | TCP connection attempted, IPv4 / IPv6 | `PID` u32, `size` u32, `daddr`, `saddr`, `dport`, `sport` |
//! | 42 / 58 | UDP datagram sent, IPv4 / IPv6 | the same |
//!
//! Integers are little-endian; addresses and ports are in network order, as on the wire.
//!
//! **Microsoft-Windows-DNS-Client** (`{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`), event 3008 (query
//! completed): `QueryName` (UTF-16, NUL-terminated), `QueryType` u32, `QueryOptions` u64,
//! `QueryStatus` u32, `QueryResults` (UTF-16, NUL-terminated: `type: 5 alias.example.net;192.0.2.50;`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use scribe_process::join::Connection;
use scribe_process::{normalise, Transport};

/// `Microsoft-Windows-Kernel-Network`.
pub const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
/// `Microsoft-Windows-DNS-Client`.
pub const DNS_CLIENT: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";

pub const TCP_CONNECT_V4: u16 = 12;
pub const TCP_CONNECT_V6: u16 = 28;
pub const UDP_SEND_V4: u16 = 42;
pub const UDP_SEND_V6: u16 = 58;
/// DNS-Client: a query completed.
pub const DNS_QUERY_COMPLETED: u16 = 3008;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetKind {
    TcpConnect,
    UdpSend,
}

impl NetKind {
    pub fn transport(self) -> Transport {
        match self {
            NetKind::TcpConnect => Transport::Tcp,
            NetKind::UdpSend => Transport::Udp,
        }
    }
}

/// A connection attempt or a datagram, with the process that made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetEvent {
    pub kind: NetKind,
    pub pid: u32,
    /// Local address; IPv4-mapped IPv6 addresses come back as IPv4.
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventError {
    #[error("event {id}: {len} bytes of user data, at least {need} expected")]
    Short { id: u16, len: usize, need: usize },
    #[error("DNS-Client event: {0}")]
    Dns(&'static str),
}

fn u16_le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u16_be(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn u32_le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

impl NetEvent {
    /// Reads a Kernel-Network event; `Ok(None)` for the events the sensor doesn't use.
    pub fn parse(id: u16, data: &[u8]) -> Result<Option<Self>, EventError> {
        let (kind, v6) = match id {
            TCP_CONNECT_V4 => (NetKind::TcpConnect, false),
            TCP_CONNECT_V6 => (NetKind::TcpConnect, true),
            UDP_SEND_V4 => (NetKind::UdpSend, false),
            UDP_SEND_V6 => (NetKind::UdpSend, true),
            _ => return Ok(None),
        };
        let alen = if v6 { 16 } else { 4 };
        let need = 8 + 2 * alen + 4;
        if data.len() < need {
            return Err(EventError::Short {
                id,
                len: data.len(),
                need,
            });
        }
        let ip = |at: usize| -> IpAddr {
            if v6 {
                let o: [u8; 16] = data[at..at + 16].try_into().expect("16 bytes");
                IpAddr::V6(Ipv6Addr::from(o))
            } else {
                IpAddr::V4(Ipv4Addr::new(
                    data[at],
                    data[at + 1],
                    data[at + 2],
                    data[at + 3],
                ))
            }
        };
        let (daddr, saddr, ports) = (8, 8 + alen, 8 + 2 * alen);
        Ok(Some(Self {
            kind,
            pid: u32_le(data, 0),
            dst: normalise(SocketAddr::new(ip(daddr), u16_be(data, ports))),
            src: normalise(SocketAddr::new(ip(saddr), u16_be(data, ports + 2))),
        }))
    }

    /// The event id and user data Windows would deliver (for tests and replays): the fields
    /// above, then zeros for the rest (`mss`, `seqnum`, `connid`, ...). Both addresses must be of
    /// one family.
    pub fn to_bytes(&self) -> (u16, Vec<u8>) {
        let v6 = self.dst.is_ipv6();
        let id = match (self.kind, v6) {
            (NetKind::TcpConnect, false) => TCP_CONNECT_V4,
            (NetKind::TcpConnect, true) => TCP_CONNECT_V6,
            (NetKind::UdpSend, false) => UDP_SEND_V4,
            (NetKind::UdpSend, true) => UDP_SEND_V6,
        };
        let mut b = Vec::with_capacity(80);
        b.extend_from_slice(&self.pid.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // size
        for a in [self.dst.ip(), self.src.ip()] {
            match a {
                IpAddr::V4(v4) => b.extend_from_slice(&v4.octets()),
                IpAddr::V6(v6) => b.extend_from_slice(&v6.octets()),
            }
        }
        b.extend_from_slice(&self.dst.port().to_be_bytes());
        b.extend_from_slice(&self.src.port().to_be_bytes());
        b.resize(b.len() + 24, 0);
        (id, b)
    }

    /// The connection report for `scribe_process::join` (the path is looked up by pid).
    pub fn connection(&self) -> Connection {
        Connection {
            transport: self.kind.transport(),
            src: self.src,
            dst: self.dst,
            pid: self.pid,
            uid: None,
            name: None,
            path: None,
        }
    }
}

/// A completed DNS query (DNS-Client event 3008).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub name: String,
    pub qtype: u32,
    /// 0: success; otherwise a Win32 / DNS error code.
    pub status: u32,
    /// The answer text as Windows formats it.
    pub results: String,
}

/// Reads a NUL-terminated UTF-16LE string at `at`; returns it and the offset after the NUL.
fn utf16z(b: &[u8], at: usize) -> Result<(String, usize), EventError> {
    let mut units = Vec::new();
    let mut i = at;
    loop {
        if i + 2 > b.len() {
            return Err(EventError::Dns("string without its terminating NUL"));
        }
        let u = u16_le(b, i);
        i += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    Ok((String::from_utf16_lossy(&units), i))
}

fn put_utf16z(b: &mut Vec<u8>, s: &str) {
    for u in s.encode_utf16() {
        b.extend_from_slice(&u.to_le_bytes());
    }
    b.extend_from_slice(&[0, 0]);
}

impl DnsQuery {
    /// Reads DNS-Client event 3008.
    pub fn parse(data: &[u8]) -> Result<Self, EventError> {
        let (name, at) = utf16z(data, 0)?;
        if data.len() < at + 16 {
            return Err(EventError::Dns(
                "too short for QueryType, QueryOptions, QueryStatus",
            ));
        }
        let qtype = u32_le(data, at);
        let status = u32_le(data, at + 12);
        let (results, _) = utf16z(data, at + 16)?;
        Ok(Self {
            name,
            qtype,
            status,
            results,
        })
    }

    /// The user data Windows would deliver (for tests and replays).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_utf16z(&mut b, &self.name);
        b.extend_from_slice(&self.qtype.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes()); // QueryOptions
        b.extend_from_slice(&self.status.to_le_bytes());
        put_utf16z(&mut b, &self.results);
        b
    }

    /// The addresses in the answer, in order, IPv4-mapped ones as IPv4; aliases (`type: 5 ...`)
    /// and anything else that isn't an address are skipped.
    pub fn addresses(&self) -> Vec<IpAddr> {
        self.results
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with("type:"))
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(|ip| normalise(SocketAddr::new(ip, 0)).ip())
            .collect()
    }
}
