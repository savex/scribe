use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

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
    /// A plaintext HTTP request seen inside an existing flow.
    Request,
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
    /// Only available for plaintext HTTP.
    pub url: Option<String>,
    pub security: Security,
    pub bytes_out: u64,
    pub kind: FlowKind,
}
