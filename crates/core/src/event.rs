use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

use crate::Notes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Quic,
}

/// Transport security observed on a flow, detected from handshake bytes, not ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Tls,
    Quic,
    Plaintext,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    NewFlow,
    /// More client bytes seen on an existing flow (e.g. the next HTTP request on a kept-alive
    /// connection); the bytes travel in [`Observation::head`].
    Payload,
    Close,
}

/// One normalized observation emitted by any sensor.
#[derive(Debug, Clone)]
pub struct FlowEvent {
    pub ts: SystemTime,
    pub pid: Option<u32>,
    pub process_path: Option<String>,
    pub proto: Protocol,
    pub src: SocketAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    /// From TLS SNI, HTTP Host header or DNS correlation.
    pub hostname: Option<String>,
    /// The ClientHello used Encrypted Client Hello: `hostname` is only the outer public name (FR-5).
    pub ech: bool,
    /// Values attached by modules, keyed by module id (the URL module writes `url`).
    pub notes: Notes,
    pub security: Security,
    pub bytes_out: u64,
    pub kind: FlowKind,
}

impl FlowEvent {
    /// The real destination name is unknown: no host name at all, or only an ECH outer name
    /// (FR-7). Such flows are tracked by IP and flagged, never dropped.
    pub fn unresolved(&self) -> bool {
        self.hostname.is_none() || self.ech
    }
}

/// Most client bytes a sensor passes on per observation.
pub const HEAD_MAX: usize = 4096;

/// What a sensor reports: the event plus the first client bytes it saw, for enrichment (SNI,
/// `Host`) and for modules that need payload.
#[derive(Debug, Clone)]
pub struct Observation {
    pub event: FlowEvent,
    /// At most [`HEAD_MAX`] bytes; `None` when the sensor saw no payload.
    pub head: Option<Vec<u8>>,
}

impl Observation {
    pub fn new(event: FlowEvent) -> Self {
        Self { event, head: None }
    }

    /// Attach `bytes`, cut to [`HEAD_MAX`].
    pub fn with_head(mut self, bytes: &[u8]) -> Self {
        self.head = Some(bytes[..bytes.len().min(HEAD_MAX)].to_vec());
        self
    }
}

impl From<FlowEvent> for Observation {
    fn from(event: FlowEvent) -> Self {
        Self::new(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn event(hostname: Option<&str>, ech: bool) -> FlowEvent {
        FlowEvent {
            ts: UNIX_EPOCH,
            pid: None,
            process_path: None,
            proto: Protocol::Tcp,
            src: "10.0.0.2:50000".parse().unwrap(),
            dst_ip: "192.0.2.12".parse().unwrap(),
            dst_port: 443,
            hostname: hostname.map(str::to_owned),
            ech,
            notes: Notes::new(),
            security: Security::Tls,
            bytes_out: 0,
            kind: FlowKind::NewFlow,
        }
    }

    #[test]
    fn unresolved_means_no_name_or_only_an_ech_outer_name() {
        assert!(!event(Some("api.example.com"), false).unresolved());
        assert!(event(None, false).unresolved());
        assert!(event(Some("public.example.com"), true).unresolved());
    }

    #[test]
    fn observations_cut_payload_to_head_max() {
        let obs = Observation::from(event(None, false)).with_head(&[7; HEAD_MAX + 1]);
        assert_eq!(obs.head.unwrap().len(), HEAD_MAX);
    }
}
