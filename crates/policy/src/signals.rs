//! The built-in caution-mode signals (specs 8.3), as plain functions of a flow's fields.

use std::net::IpAddr;

use scribe_core::Protocol;

/// Reason ids of the built-in signals and alerts.
pub const RAW_IP: &str = "raw_ip";
pub const UNUSUAL_PORT: &str = "unusual_port";
pub const HIGH_ENTROPY: &str = "high_entropy";
pub const NEW_TLD: &str = "new_tld";
pub const NEW_PROCESS: &str = "new_process";
pub const THREAT_LIST: &str = "threat_list";
pub const UNLISTED_HOST: &str = "unlisted_host";
pub const PLAINTEXT: &str = "plaintext";

/// Whether `host` is an IP address written as text (how flows without a name are keyed).
pub fn is_ip(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok()
}

/// The top-level domain of a host name (`net` for `shop.example.net`); `None` for IPs and
/// single-label names.
pub fn tld(host: &str) -> Option<&str> {
    if is_ip(host) {
        return None;
    }
    let host = host.trim_end_matches('.');
    host.rsplit_once('.')
        .map(|(_, tld)| tld)
        .filter(|t| !t.is_empty())
}

/// Shannon entropy of `s` in bits per character (0 for an empty string).
pub fn shannon_bits(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let mut n = 0u32;
    for b in s.bytes() {
        counts[usize::from(b)] += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    let n = f64::from(n);
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

/// The longest label of a host name (the first one on a tie).
pub fn longest_label(host: &str) -> &str {
    host.split('.')
        .fold("", |best, l| if l.len() > best.len() { l } else { best })
}

/// A random-looking (DGA-style) name: its longest label has at least `min_len` characters and at
/// least `min_bits` bits of entropy per character. IPs never match.
pub fn high_entropy(host: &str, min_len: usize, min_bits: f64) -> bool {
    if is_ip(host) {
        return false;
    }
    let label = longest_label(host);
    label.len() >= min_len && shannon_bits(label) >= min_bits
}

/// Usual destination ports per transport (`policy.usual_ports`); QUIC counts as UDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsualPorts {
    pub tcp: Vec<u16>,
    pub udp: Vec<u16>,
}

impl Default for UsualPorts {
    fn default() -> Self {
        Self {
            tcp: vec![22, 53, 80, 443, 465, 587, 853, 993, 995],
            udp: vec![53, 123, 443, 853, 5353],
        }
    }
}

impl UsualPorts {
    pub fn is_usual(&self, proto: Protocol, port: u16) -> bool {
        match proto {
            Protocol::Tcp => self.tcp.contains(&port),
            Protocol::Udp | Protocol::Quic => self.udp.contains(&port),
        }
    }
}
