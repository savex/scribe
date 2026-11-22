//! Fill in what a sensor's observation lacks: transport security, the ECH flag and the host name
//! (FR-3, FR-4, FR-5). Order for the host name: TLS SNI (over TCP or in a QUIC Initial), then the
//! HTTP `Host` header, then a name the sensor already reported (macOS gives one), then the DNS cache
//! for the destination IP.
//!
//! A UDP observation whose first bytes are a client Initial that carries the whole ClientHello
//! becomes a QUIC flow. ClientHellos spread over several Initials need per-flow state: the
//! pipeline (phase 5) keeps a [`crate::InitialReassembler`] per flow and calls [`Enricher::apply_hello`].
//!
//! DNS answers come from the server, so sensors report them separately: the pipeline (phase 5)
//! calls [`Enricher::observe_dns_response`] with response bytes (pcap, eBPF) or
//! [`Enricher::observe_dns_answer`] with answers the OS already decoded (Windows DNS-Client events).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use scribe_core::{Clock, FlowEvent, Observation, Protocol, Security};

use crate::dns::{parse_response, DnsCache};
use crate::http::host_header;
use crate::quic::client_hello_from_initial;
use crate::tls::{detect_security, parse_client_hello, ClientHello};

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

    /// Mark `event` as QUIC and take the name and ECH flag from its ClientHello.
    pub fn apply_hello(event: &mut FlowEvent, hello: ClientHello) {
        event.proto = Protocol::Quic;
        event.security = Security::Quic;
        event.ech |= hello.ech;
        if hello.sni.is_some() {
            event.hostname = hello.sni;
        }
    }

    /// Complete the observation's event in place.
    pub fn enrich(&self, obs: &mut Observation) {
        let event = &mut obs.event;
        if let (Some(head), Protocol::Udp | Protocol::Quic) = (obs.head.as_deref(), event.proto) {
            if let Some(hello) = client_hello_from_initial(head) {
                Self::apply_hello(event, hello);
            } else if event.security == Security::Unknown {
                event.security = if looks_like_quic(head) {
                    Security::Quic
                } else {
                    Security::Plaintext
                };
            }
        }
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

/// A QUIC v1 / v2 long header whose Initial could not be read (later packet, ClientHello split
/// over several datagrams): still QUIC, not plaintext.
fn looks_like_quic(datagram: &[u8]) -> bool {
    datagram.len() >= 5
        && datagram[0] & 0xc0 == 0xc0
        && matches!(
            u32::from_be_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]),
            crate::quic::VERSION_1 | crate::quic::VERSION_2
        )
}
