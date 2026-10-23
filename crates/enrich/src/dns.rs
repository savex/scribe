use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// IP -> hostname map built from observed DNS answers, honoring record TTLs.
#[derive(Debug, Default)]
pub struct DnsCache {
    entries: HashMap<IpAddr, (String, Instant)>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, ip: IpAddr, hostname: impl Into<String>, ttl: Duration) {
        self.entries.insert(ip, (hostname.into(), Instant::now() + ttl));
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<&str> {
        self.entries
            .get(ip)
            .filter(|(_, expires)| *expires > Instant::now())
            .map(|(name, _)| name.as_str())
    }

    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, (_, expires)| *expires > now);
    }
}
