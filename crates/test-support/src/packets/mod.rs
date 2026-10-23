//! Deterministic packet builders for fixtures and the sensor traffic generator.
//! Addresses come from documentation ranges (RFC 5737 / RFC 3849) unless a test needs a real one.

pub mod dns;
pub mod http;
pub mod net;
pub mod pcap;
pub mod tls;

pub use net::{tcp_frame, udp_frame, TcpFlow};
pub use pcap::write_pcap;
