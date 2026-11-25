//! Flows from the Kernel-Network events alone, for when Npcap isn't installed: no first bytes, so
//! no SNI or URLs, but every connection with its process (host names come from the DNS-Client
//! events through the DNS cache).
//!
//! A TCP connection attempt is a new flow. A UDP datagram is a new flow the first time its process
//! sends from that local address to that destination, and again after [`UDP_REPEAT`] without one
//! (Kernel-Network reports every datagram). The observations carry no process: the sensor reports
//! the event to `scribe_process::join` first, which fills it in.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use scribe_core::{FlowEvent, FlowKind, Notes, Observation, Protocol, Security};

use crate::events::{NetEvent, NetKind};

/// A UDP flow is reported again after this long without a datagram.
pub const UDP_REPEAT: Duration = Duration::from_secs(30);
/// Most UDP flows remembered; the oldest go first.
pub const MAX_UDP: usize = 65_536;

#[derive(Default)]
pub struct EtwFlows {
    udp: HashMap<(u32, SocketAddr, SocketAddr), SystemTime>,
}

impl EtwFlows {
    pub fn new() -> Self {
        Self::default()
    }

    /// The new flow this event starts, if any.
    pub fn observe(&mut self, e: &NetEvent, now: SystemTime) -> Option<Observation> {
        let proto = match e.kind {
            NetKind::TcpConnect => Protocol::Tcp,
            NetKind::UdpSend => {
                let key = (e.pid, e.src, e.dst);
                let last = self.udp.insert(key, now);
                if last.is_some_and(|t| now.duration_since(t).unwrap_or_default() < UDP_REPEAT) {
                    return None;
                }
                if self.udp.len() > MAX_UDP {
                    self.udp
                        .retain(|_, t| now.duration_since(*t).unwrap_or_default() < UDP_REPEAT);
                    if self.udp.len() > MAX_UDP {
                        self.udp.clear();
                    }
                }
                Protocol::Udp
            }
        };
        Some(Observation::new(FlowEvent {
            ts: now,
            pid: None,
            process_path: None,
            proto,
            src: e.src,
            dst_ip: e.dst.ip(),
            dst_port: e.dst.port(),
            hostname: None,
            ech: false,
            notes: Notes::new(),
            security: Security::Unknown,
            bytes_out: 0,
            kind: FlowKind::NewFlow,
        }))
    }

    pub fn udp_flows(&self) -> usize {
        self.udp.len()
    }
}
