//! The records the eBPF programs write to the ring buffer: `struct scribe_flow` in
//! `src/bpf/scribe.h`, read here field by field (no `unsafe`, any input). Integers are in the
//! byte order of this machine, as the kernel wrote them; addresses in network order.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use scribe_process::{normalise, Transport};

/// `sizeof(struct scribe_flow)`.
pub const RECORD_SIZE: usize = 88;
/// `SCRIBE_RECORD_VERSION`: a record of another version is refused.
pub const RECORD_VERSION: u8 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

const TS_NS: usize = 0;
const CGROUP_ID: usize = 8;
const TGID: usize = 16;
const PID: usize = 20;
const UID: usize = 24;
const FAMILY: usize = 28;
const KIND: usize = 30;
const VERSION: usize = 31;
const SPORT: usize = 32;
const DPORT: usize = 34;
const SADDR: usize = 36;
const DADDR: usize = 52;
const COMM: usize = 68;
const COMM_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// `tcp_connect()`: a new outgoing TCP connection.
    TcpConnect = 1,
    /// `udp_sendmsg()` / `udpv6_sendmsg()`: a datagram of a flow (deduplicated in the kernel).
    UdpSend = 2,
}

impl RecordKind {
    pub fn transport(self) -> Transport {
        match self {
            RecordKind::TcpConnect => Transport::Tcp,
            RecordKind::UdpSend => Transport::Udp,
        }
    }
}

/// One connection with the process that made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub kind: RecordKind,
    pub ts_ns: u64,
    pub cgroup_id: u64,
    /// Process id.
    pub tgid: u32,
    /// Thread id.
    pub pid: u32,
    pub uid: u32,
    /// The thread's name, up to 15 bytes.
    pub comm: String,
    /// Local address; `0.0.0.0` / `::` for a UDP socket not bound to one address.
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("record of {0} bytes, expected {RECORD_SIZE}")]
    Size(usize),
    #[error("record version {0}, expected {RECORD_VERSION}")]
    Version(u8),
    #[error("unknown record kind {0}")]
    Kind(u8),
    #[error("unknown address family {0}")]
    Family(u16),
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

fn ip_at(b: &[u8], at: usize, family: u16) -> IpAddr {
    if family == AF_INET {
        IpAddr::V4(Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3]))
    } else {
        let octets: [u8; 16] = b[at..at + 16].try_into().expect("16 bytes");
        IpAddr::V6(Ipv6Addr::from(octets))
    }
}

fn put_ip(b: &mut [u8], at: usize, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => b[at..at + 4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => b[at..at + 16].copy_from_slice(&v6.octets()),
    }
}

impl Record {
    /// Reads one ring-buffer record. IPv4-mapped IPv6 addresses come back as IPv4, so a flow
    /// from a dual-stack socket matches the packets of it.
    pub fn parse(b: &[u8]) -> Result<Self, RecordError> {
        if b.len() != RECORD_SIZE {
            return Err(RecordError::Size(b.len()));
        }
        if b[VERSION] != RECORD_VERSION {
            return Err(RecordError::Version(b[VERSION]));
        }
        let kind = match b[KIND] {
            1 => RecordKind::TcpConnect,
            2 => RecordKind::UdpSend,
            other => return Err(RecordError::Kind(other)),
        };
        let family = u16_at(b, FAMILY);
        if family != AF_INET && family != AF_INET6 {
            return Err(RecordError::Family(family));
        }
        let comm = &b[COMM..COMM + COMM_LEN];
        let comm_len = comm.iter().position(|&c| c == 0).unwrap_or(COMM_LEN);
        Ok(Self {
            kind,
            ts_ns: u64_at(b, TS_NS),
            cgroup_id: u64_at(b, CGROUP_ID),
            tgid: u32_at(b, TGID),
            pid: u32_at(b, PID),
            uid: u32_at(b, UID),
            comm: String::from_utf8_lossy(&comm[..comm_len]).into_owned(),
            src: normalise(SocketAddr::new(ip_at(b, SADDR, family), u16_at(b, SPORT))),
            dst: normalise(SocketAddr::new(ip_at(b, DADDR, family), u16_at(b, DPORT))),
        })
    }

    /// The bytes the kernel would write for this record (for tests and replays). Both addresses
    /// must be of one family.
    pub fn to_bytes(&self) -> [u8; RECORD_SIZE] {
        let mut b = [0u8; RECORD_SIZE];
        b[TS_NS..TS_NS + 8].copy_from_slice(&self.ts_ns.to_ne_bytes());
        b[CGROUP_ID..CGROUP_ID + 8].copy_from_slice(&self.cgroup_id.to_ne_bytes());
        b[TGID..TGID + 4].copy_from_slice(&self.tgid.to_ne_bytes());
        b[PID..PID + 4].copy_from_slice(&self.pid.to_ne_bytes());
        b[UID..UID + 4].copy_from_slice(&self.uid.to_ne_bytes());
        let family = if self.dst.is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        };
        b[FAMILY..FAMILY + 2].copy_from_slice(&family.to_ne_bytes());
        b[KIND] = self.kind as u8;
        b[VERSION] = RECORD_VERSION;
        b[SPORT..SPORT + 2].copy_from_slice(&self.src.port().to_ne_bytes());
        b[DPORT..DPORT + 2].copy_from_slice(&self.dst.port().to_ne_bytes());
        put_ip(&mut b, SADDR, self.src.ip());
        put_ip(&mut b, DADDR, self.dst.ip());
        let comm = self.comm.as_bytes();
        let n = comm.len().min(COMM_LEN - 1);
        b[COMM..COMM + n].copy_from_slice(&comm[..n]);
        b
    }
}
