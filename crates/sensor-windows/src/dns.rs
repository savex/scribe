//! Answers Windows already decoded (DNS-Client event 3008) as a DNS response message, so they take
//! the same way into the DNS cache as answers read from packets (a `DnsResponse` observation).
//!
//! The message holds the question and one A / AAAA record per address, all under the queried
//! name: the cache maps each address to that name, as it would after following the aliases. ETW
//! reports no TTL, so every answer gets [`DNS_TTL`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime};

use scribe_core::{FlowEvent, FlowKind, Notes, Observation, Protocol, Security};

use crate::events::DnsQuery;

/// The TTL given to answers from ETW.
pub const DNS_TTL: Duration = Duration::from_secs(300);

/// Most addresses put in one message, so it stays within `HEAD_MAX` (4 KiB).
pub const MAX_ANSWERS: usize = 128;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// The query's name in DNS wire format; `None` for a name no DNS message can carry.
fn encode_name(name: &str, out: &mut Vec<u8>) -> Option<()> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Some(())
}

/// A DNS response message for a successful query with at least one address; `None` otherwise.
pub fn response(q: &DnsQuery) -> Option<Vec<u8>> {
    let addrs: Vec<IpAddr> = q.addresses().into_iter().take(MAX_ANSWERS).collect();
    if q.status != 0 || addrs.is_empty() {
        return None;
    }
    let qtype = match q.qtype {
        28 => TYPE_AAAA,
        _ => TYPE_A,
    };
    let mut m = Vec::with_capacity(64 + 28 * addrs.len());
    m.extend_from_slice(&0u16.to_be_bytes()); // id
    m.extend_from_slice(&0x8180u16.to_be_bytes()); // response, recursion desired and available
    m.extend_from_slice(&1u16.to_be_bytes()); // questions
    m.extend_from_slice(&(addrs.len() as u16).to_be_bytes()); // answers
    m.extend_from_slice(&[0, 0, 0, 0]); // authority, additional
    encode_name(&q.name, &mut m)?;
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&CLASS_IN.to_be_bytes());
    let ttl = DNS_TTL.as_secs() as u32;
    for ip in addrs {
        m.extend_from_slice(&0xC00Cu16.to_be_bytes()); // the question's name
        let (rtype, rdata): (u16, Vec<u8>) = match ip {
            IpAddr::V4(v4) => (TYPE_A, v4.octets().to_vec()),
            IpAddr::V6(v6) => (TYPE_AAAA, v6.octets().to_vec()),
        };
        m.extend_from_slice(&rtype.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(&rdata);
    }
    Some(m)
}

/// The `DnsResponse` observation for a completed query, if it answered with addresses. The
/// observation names no flow (`0.0.0.0:0` → `0.0.0.0:53`): it only feeds the DNS cache.
pub fn observation(q: &DnsQuery, ts: SystemTime) -> Option<Observation> {
    let msg = response(q)?;
    let event = FlowEvent {
        ts,
        pid: None,
        process_path: None,
        proto: Protocol::Udp,
        src: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        dst_port: 53,
        hostname: None,
        ech: false,
        notes: Notes::new(),
        security: Security::Unknown,
        bytes_out: 0,
        kind: FlowKind::DnsResponse,
    };
    Some(Observation::new(event).with_head(&msg))
}
