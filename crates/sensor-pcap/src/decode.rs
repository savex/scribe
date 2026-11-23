//! Packet decoding: link layer → IPv4 / IPv6 → TCP / UDP. Anything else, and anything malformed,
//! decodes to `None`; nothing here panics on any input.
//!
//! Link types (pcap `LINKTYPE_*` / `DLT_*`): Ethernet with 802.1Q / 802.1ad tags, BSD loopback
//! (`NULL`, host byte order, and `LOOP`, network byte order: macOS `lo0`, Npcap loopback), raw IP,
//! Linux cooked capture v1 and v2 (the Linux `any` device).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::SystemTime;

pub const LINKTYPE_NULL: i32 = 0;
pub const LINKTYPE_ETHERNET: i32 = 1;
/// `DLT_RAW` is 12 on most systems and 14 on OpenBSD; libpcap reports 12 or 14 live and files say 101.
pub const LINKTYPE_RAW_DLT: i32 = 12;
pub const LINKTYPE_RAW_DLT_OPENBSD: i32 = 14;
pub const LINKTYPE_RAW: i32 = 101;
pub const LINKTYPE_LOOP: i32 = 108;
pub const LINKTYPE_LINUX_SLL: i32 = 113;
pub const LINKTYPE_IPV4: i32 = 228;
pub const LINKTYPE_IPV6: i32 = 229;
pub const LINKTYPE_LINUX_SLL2: i32 = 276;

/// Whether this decoder understands a link type.
pub fn supported(linktype: i32) -> bool {
    matches!(
        linktype,
        LINKTYPE_NULL
            | LINKTYPE_ETHERNET
            | LINKTYPE_RAW_DLT
            | LINKTYPE_RAW_DLT_OPENBSD
            | LINKTYPE_RAW
            | LINKTYPE_LOOP
            | LINKTYPE_LINUX_SLL
            | LINKTYPE_IPV4
            | LINKTYPE_IPV6
            | LINKTYPE_LINUX_SLL2
    )
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp { flags: u8, seq: u32 },
    Udp,
}

/// One decoded TCP segment or UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub ts: SystemTime,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub transport: Transport,
    pub payload: &'a [u8],
}

impl Packet<'_> {
    pub fn is_tcp(&self) -> bool {
        matches!(self.transport, Transport::Tcp { .. })
    }

    pub fn tcp_flags(&self) -> u8 {
        match self.transport {
            Transport::Tcp { flags, .. } => flags,
            Transport::Udp => 0,
        }
    }
}

fn u16_be(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// Decode one captured frame of the given link type.
pub fn decode(linktype: i32, frame: &[u8], ts: SystemTime) -> Option<Packet<'_>> {
    let (ethertype, ip) = match linktype {
        LINKTYPE_ETHERNET => ethernet(frame)?,
        LINKTYPE_NULL | LINKTYPE_LOOP => {
            let raw: [u8; 4] = frame.get(..4)?.try_into().ok()?;
            let family = if linktype == LINKTYPE_LOOP {
                u32::from_be_bytes(raw)
            } else {
                // Host byte order of the capturing machine: accept either.
                let le = u32::from_le_bytes(raw);
                if le <= 0xff {
                    le
                } else {
                    u32::from_be_bytes(raw)
                }
            };
            let ethertype = match family {
                2 => 0x0800,
                10 | 24 | 28 | 30 => 0x86dd, // AF_INET6 on Linux, BSDs, macOS
                _ => return None,
            };
            (ethertype, frame.get(4..)?)
        }
        LINKTYPE_RAW_DLT | LINKTYPE_RAW_DLT_OPENBSD | LINKTYPE_RAW => match frame.first()? >> 4 {
            4 => (0x0800, frame),
            6 => (0x86dd, frame),
            _ => return None,
        },
        LINKTYPE_IPV4 => (0x0800, frame),
        LINKTYPE_IPV6 => (0x86dd, frame),
        LINKTYPE_LINUX_SLL => (u16_be(frame, 14)?, frame.get(16..)?),
        LINKTYPE_LINUX_SLL2 => (u16_be(frame, 0)?, frame.get(20..)?),
        _ => return None,
    };
    let (src, dst, proto, segment) = match ethertype {
        0x0800 => ipv4(ip)?,
        0x86dd => ipv6(ip)?,
        _ => return None,
    };
    transport(proto, src, dst, segment, ts)
}

fn ethernet(frame: &[u8]) -> Option<(u16, &[u8])> {
    let mut ethertype = u16_be(frame, 12)?;
    let mut at = 14;
    // Up to two VLAN tags (802.1Q, 802.1ad QinQ).
    for _ in 0..2 {
        if ethertype == 0x8100 || ethertype == 0x88a8 {
            ethertype = u16_be(frame, at + 2)?;
            at += 4;
        }
    }
    Some((ethertype, frame.get(at..)?))
}

fn ipv4(ip: &[u8]) -> Option<(IpAddr, IpAddr, u8, &[u8])> {
    let first = *ip.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(first & 0x0f) * 4;
    let total = usize::from(u16_be(ip, 2)?);
    if ihl < 20 || total < ihl || total > ip.len() {
        return None;
    }
    // Fragments: only an unfragmented packet has whole TCP / UDP headers and payload.
    let frag = u16_be(ip, 6)?;
    if frag & 0x2000 != 0 || frag & 0x1fff != 0 {
        return None;
    }
    let src: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
    let dst: [u8; 4] = ip.get(16..20)?.try_into().ok()?;
    Some((
        IpAddr::V4(Ipv4Addr::from(src)),
        IpAddr::V4(Ipv4Addr::from(dst)),
        *ip.get(9)?,
        ip.get(ihl..total)?,
    ))
}

fn ipv6(ip: &[u8]) -> Option<(IpAddr, IpAddr, u8, &[u8])> {
    if ip.first()? >> 4 != 6 {
        return None;
    }
    let len = usize::from(u16_be(ip, 4)?);
    let body = ip.get(40..40 + len)?;
    let src: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
    let dst: [u8; 16] = ip.get(24..40)?.try_into().ok()?;
    let mut next = *ip.get(6)?;
    let mut at = 0usize;
    // Skip extension headers (at most 8); fragments are left out like IPv4 ones.
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                let h = body.get(at..at + 2)?;
                next = h[0];
                at += (usize::from(h[1]) + 1) * 8;
            }
            44 => {
                let h = body.get(at..at + 8)?;
                let offset_more = u16::from_be_bytes([h[2], h[3]]);
                if offset_more & 0xfff9 != 0 {
                    return None;
                }
                next = h[0];
                at += 8;
            }
            _ => break,
        }
    }
    Some((
        IpAddr::V6(Ipv6Addr::from(src)),
        IpAddr::V6(Ipv6Addr::from(dst)),
        next,
        body.get(at..)?,
    ))
}

fn transport<'a>(
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    seg: &'a [u8],
    ts: SystemTime,
) -> Option<Packet<'a>> {
    let sport = u16_be(seg, 0)?;
    let dport = u16_be(seg, 2)?;
    let (transport, payload) = match proto {
        6 => {
            let offset = usize::from(seg.get(12)? >> 4) * 4;
            if offset < 20 {
                return None;
            }
            let seq = u32::from_be_bytes(seg.get(4..8)?.try_into().ok()?);
            (
                Transport::Tcp {
                    flags: *seg.get(13)?,
                    seq,
                },
                seg.get(offset..)?,
            )
        }
        17 => {
            let len = usize::from(u16_be(seg, 4)?);
            if len < 8 || len > seg.len() {
                return None;
            }
            (Transport::Udp, seg.get(8..len)?)
        }
        _ => return None,
    };
    Some(Packet {
        ts,
        src: SocketAddr::new(src, sport),
        dst: SocketAddr::new(dst, dport),
        transport,
        payload,
    })
}
