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
    /// Values attached by modules, keyed by module id (the URL module writes `url`).
    pub notes: Notes,
    pub security: Security,
    pub bytes_out: u64,
    pub kind: FlowKind,
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
