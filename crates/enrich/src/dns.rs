//! DNS: parse responses and remember which name each answer IP belongs to (FR-3).
//!
//! An IP maps back to the name the client **asked for**: for `cdn.example.com CNAME
//! edge.example.net`, `edge.example.net A 192.0.2.50`, the IP `192.0.2.50` maps to
//! `cdn.example.com`. Entries expire with the shortest TTL along the chain, measured with
//! [`Clock`]. The parser never panics; compressed names are followed with a jump limit.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use scribe_core::{Clock, SystemClock};

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// Owner name, lower case, no trailing dot.
    pub name: String,
    pub ttl: u32,
    pub record: Record,
}

/// The parts of a DNS response the cache needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub id: u16,
    /// The first question's name.
    pub question: String,
    /// A, AAAA and CNAME answers of class IN; other records are skipped.
    pub answers: Vec<Answer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    /// A query, not a response.
    NotResponse,
    /// The server reported an error (NXDOMAIN, SERVFAIL, …).
    Failed(u8),
    Malformed,
}

/// Parse a DNS message carried over UDP (or TCP without its length prefix).
pub fn parse_response(msg: &[u8]) -> Result<Response, DnsError> {
    let h = msg.get(..12).ok_or(DnsError::Malformed)?;
    let id = u16::from_be_bytes([h[0], h[1]]);
    let flags = u16::from_be_bytes([h[2], h[3]]);
    if flags & 0x8000 == 0 {
        return Err(DnsError::NotResponse);
    }
    let rcode = (flags & 0x000f) as u8;
    if rcode != 0 {
        return Err(DnsError::Failed(rcode));
    }
    let qd = u16::from_be_bytes([h[4], h[5]]);
    let an = u16::from_be_bytes([h[6], h[7]]);
    if qd == 0 {
        return Err(DnsError::Malformed);
    }
    let mut pos = 12;
    let mut question = None;
    for _ in 0..qd {
        let (name, next) = read_name(msg, pos)?;
        pos = next
            .checked_add(4)
            .filter(|&p| p <= msg.len())
            .ok_or(DnsError::Malformed)?;
        question.get_or_insert(name);
    }
    let mut answers = Vec::new();
    for _ in 0..an {
        let (name, next) = read_name(msg, pos)?;
        let fixed = msg.get(next..next + 10).ok_or(DnsError::Malformed)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let len = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let start = next + 10;
        let data = msg.get(start..start + len).ok_or(DnsError::Malformed)?;
        pos = start + len;
        if class != CLASS_IN {
            continue;
        }
        let record = match (rtype, data.len()) {
            (TYPE_A, 4) => Record::A(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
            (TYPE_AAAA, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(data);
                Record::Aaaa(Ipv6Addr::from(b))
            }
            (TYPE_CNAME, _) => Record::Cname(read_name(msg, start)?.0),
            _ => continue,
        };
        answers.push(Answer { name, ttl, record });
    }
    Ok(Response {
        id,
        question: question.expect("qd > 0"),
        answers,
    })
}

/// Read a (possibly compressed) name at `pos`; returns it and the position after it.
fn read_name(msg: &[u8], mut pos: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut after = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos).ok_or(DnsError::Malformed)? as usize;
        match len {
            0 => {
                let end = after.unwrap_or(pos + 1);
                return Ok((name, end));
            }
            l if l & 0xc0 == 0xc0 => {
                let lo = *msg.get(pos + 1).ok_or(DnsError::Malformed)? as usize;
                jumps += 1;
                if jumps > 16 {
                    return Err(DnsError::Malformed);
                }
                after.get_or_insert(pos + 2);
                pos = ((l & 0x3f) << 8) | lo;
            }
            l if l <= 63 => {
                let label = msg.get(pos + 1..pos + 1 + l).ok_or(DnsError::Malformed)?;
                if !name.is_empty() {
                    name.push('.');
                }
                for &b in label {
                    if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                        return Err(DnsError::Malformed);
                    }
                    name.push(b.to_ascii_lowercase() as char);
                }
                if name.len() > 253 {
                    return Err(DnsError::Malformed);
                }
                pos += 1 + l;
            }
            _ => return Err(DnsError::Malformed),
        }
    }
}

/// Longest an answer is kept, whatever its TTL.
pub const MAX_TTL: Duration = Duration::from_secs(24 * 3600);

/// IP → queried host name, from observed DNS answers.
pub struct DnsCache {
    entries: HashMap<IpAddr, (String, SystemTime)>,
    clock: Arc<dyn Clock>,
    max_entries: usize,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock), 100_000)
    }
}

impl DnsCache {
    pub fn new(clock: Arc<dyn Clock>, max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            clock,
            max_entries: max_entries.max(1),
        }
    }

    pub fn insert(&mut self, ip: IpAddr, hostname: impl Into<String>, ttl: Duration) {
        let expires = self.clock.now() + ttl.min(MAX_TTL);
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&ip) {
            self.purge_expired();
            if self.entries.len() >= self.max_entries {
                // Drop the entry that expires first.
                if let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(ip, _)| *ip)
                {
                    self.entries.remove(&oldest);
                }
            }
        }
        self.entries.insert(ip, (hostname.into(), expires));
    }

    /// Learn from a response: every A / AAAA answer reachable from the question through CNAMEs
    /// maps to the question's name. Returns how many IPs were learned.
    pub fn observe(&mut self, response: &Response) -> usize {
        let mut learned = 0;
        // Names that lead to the question, with the shortest TTL on the way.
        let mut chain: HashMap<&str, u32> = HashMap::from([(response.question.as_str(), u32::MAX)]);
        for _ in 0..8 {
            let mut grew = false;
            for a in &response.answers {
                if let (Record::Cname(target), Some(&ttl)) = (&a.record, chain.get(a.name.as_str()))
                {
                    let t = ttl.min(a.ttl);
                    if chain.get(target.as_str()).is_none_or(|&old| t < old) {
                        chain.insert(target, t);
                        grew = true;
                    }
                }
            }
            if !grew {
                break;
            }
        }
        for a in &response.answers {
            let Some(&ttl) = chain.get(a.name.as_str()) else {
                continue;
            };
            let ip = match a.record {
                Record::A(ip) => IpAddr::V4(ip),
                Record::Aaaa(ip) => IpAddr::V6(ip),
                Record::Cname(_) => continue,
            };
            let ttl = Duration::from_secs(u64::from(ttl.min(a.ttl)));
            self.insert(ip, response.question.clone(), ttl);
            learned += 1;
        }
        learned
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<&str> {
        let now = self.clock.now();
        self.entries
            .get(ip)
            .filter(|(_, expires)| *expires > now)
            .map(|(name, _)| name.as_str())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn purge_expired(&mut self) {
        let now = self.clock.now();
        self.entries.retain(|_, (_, expires)| *expires > now);
    }
}
