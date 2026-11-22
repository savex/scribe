//! Fill in what a sensor's observation lacks: transport security, the ECH flag and the host name
//! (FR-3, FR-4, FR-5). Order for the host name: TLS SNI, then the HTTP `Host` header, then a name
//! the sensor already reported (macOS gives one), then the DNS cache for the destination IP.
//!
//! DNS answers come from the server, so sensors report them separately: the pipeline (phase 5)
//! calls [`Enricher::observe_dns_response`] with response bytes (pcap, eBPF) or
//! [`Enricher::observe_dns_answer`] with answers the OS already decoded (Windows DNS-Client events).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use scribe_core::{Clock, Observation, Protocol, Security};

use crate::dns::{parse_response, DnsCache};
use crate::http::host_header;
use crate::tls::{detect_security, parse_client_hello};

pub struct Enricher {
    dns: DnsCache,
}

impl Enricher {
    pub fn new(clock: Arc<dyn Clock>, max_dns_entries: usize) -> Self {
        Self {
            dns: DnsCache::new(clock, max_dns_entries),
        }
    }

    /// Learn from a DNS response; returns how many IPs it named.
    pub fn observe_dns_response(&mut self, msg: &[u8]) -> usize {
        match parse_response(msg) {
            Ok(r) => self.dns.observe(&r),
            Err(_) => 0,
        }
    }

    /// Learn one answer the OS already decoded.
    pub fn observe_dns_answer(&mut self, name: &str, ip: IpAddr, ttl: Duration) {
        if let Some(name) = crate::tls::valid_host(name.as_bytes()) {
            self.dns.insert(ip, name, ttl);
        }
    }

    pub fn dns(&self) -> &DnsCache {
        &self.dns
    }

    /// Complete the observation's event in place.
    pub fn enrich(&self, obs: &mut Observation) {
        let event = &mut obs.event;
        if let (Some(head), Protocol::Tcp) = (obs.head.as_deref(), event.proto) {
            if event.security == Security::Unknown {
                event.security = detect_security(head);
            }
            let named = match event.security {
                Security::Tls => parse_client_hello(head).ok().and_then(|h| {
                    event.ech |= h.ech;
                    h.sni
                }),
                Security::Plaintext => host_header(head),
                _ => None,
            };
            if named.is_some() {
                event.hostname = named;
            }
        }
        if event.hostname.is_none() {
            event.hostname = self.dns.lookup(&event.dst_ip).map(str::to_owned);
        }
    }
}
