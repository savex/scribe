//! Threat lists (specs 8.3): host names and IPs from local files, in three formats. Lines that
//! can't be read are skipped and counted, so one bad line never drops a whole list.

use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatFormat {
    /// One domain per line; it also covers its subdomains.
    Domains,
    /// A hosts file: `<ip> <name> [<name>…]`; the IP is ignored, `localhost` entries too.
    Hosts,
    /// One IP address or CIDR network per line.
    Ips,
}

/// What [`ThreatSet::load`] read from one list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadReport {
    pub added: usize,
    pub skipped: usize,
}

/// Every configured threat list, merged.
#[derive(Debug, Clone, Default)]
pub struct ThreatSet {
    domains: HashSet<String>,
    ips: HashSet<IpAddr>,
    nets: Vec<(IpAddr, u8)>,
}

fn normalise(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    ok.then_some(name)
}

fn parse_net(text: &str) -> Option<(IpAddr, u8)> {
    let (ip, len) = text.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (len <= max).then_some((ip, len))
}

fn in_net(ip: IpAddr, (net, len): (IpAddr, u8)) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(len))
            };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(len))
            };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

impl ThreatSet {
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.ips.is_empty() && self.nets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.domains.len() + self.ips.len() + self.nets.len()
    }

    /// Add every entry of `other` (one list merged into the set of all lists).
    pub fn merge(&mut self, other: &ThreatSet) {
        self.domains.extend(other.domains.iter().cloned());
        self.ips.extend(other.ips.iter().copied());
        self.nets.extend(other.nets.iter().copied());
    }

    /// Add a list's text. `#` starts a comment; blank lines are ignored.
    pub fn load(&mut self, format: ThreatFormat, text: &str) -> LoadReport {
        let mut report = LoadReport::default();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let ok = match format {
                ThreatFormat::Domains => self.add_domain(line),
                ThreatFormat::Ips => self.add_ip(line),
                ThreatFormat::Hosts => {
                    let mut fields = line.split_whitespace();
                    if !fields.next().is_some_and(|f| f.parse::<IpAddr>().is_ok()) {
                        report.skipped += 1;
                        continue;
                    }
                    let mut any = false;
                    for name in fields {
                        if name.eq_ignore_ascii_case("localhost")
                            || name.to_ascii_lowercase().starts_with("localhost.")
                        {
                            continue;
                        }
                        any |= self.add_domain(name);
                    }
                    any
                }
            };
            if ok {
                report.added += 1;
            } else {
                report.skipped += 1;
            }
        }
        report
    }

    /// Add one domain; it also covers its subdomains.
    pub fn add_domain(&mut self, name: &str) -> bool {
        match normalise(name) {
            Some(n) if !crate::signals::is_ip(&n) => {
                self.domains.insert(n);
                true
            }
            _ => false,
        }
    }

    /// Add one IP address or CIDR network.
    pub fn add_ip(&mut self, text: &str) -> bool {
        let text = text.trim();
        if let Ok(ip) = text.parse::<IpAddr>() {
            self.ips.insert(ip);
            true
        } else if let Some(net) = parse_net(text) {
            self.nets.push(net);
            true
        } else {
            false
        }
    }

    /// The host name or one of its parent domains is listed.
    pub fn matches_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let mut rest = host.as_str();
        loop {
            if self.domains.contains(rest) {
                return true;
            }
            match rest.split_once('.') {
                Some((_, parent)) => rest = parent,
                None => return false,
            }
        }
    }

    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip) || self.nets.iter().any(|&net| in_net(ip, net))
    }
}
