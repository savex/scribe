//! Windows sensor based on ETW (plan option 8A).
//!
//! Two parts meet in user space, as in the Linux eBPF sensor:
//! - **who**: a real-time ETW session on `Microsoft-Windows-Kernel-Network` reports every TCP
//!   connection attempt and UDP datagram with the process that made it ([`events::NetEvent`]),
//!   and `Microsoft-Windows-DNS-Client` every completed query with the addresses Windows resolved
//!   ([`events::DnsQuery`], passed on as a DNS response by [`dns`]);
//! - **what**: packets from Npcap through the pcap sensor's flow tracker (first bytes for SNI and
//!   URLs, DNS, QUIC, closes). Without Npcap, [`flows::EtwFlows`] makes the flows from the
//!   Kernel-Network events alone.
//!
//! `scribe_process::join` matches the two by address. [`events`], [`dns`] and [`flows`] build on
//! every system (their tests run everywhere); the ETW session is Windows only.

pub mod dns;
pub mod events;
pub mod flows;

pub use events::{DnsQuery, EventError, NetEvent, NetKind};
pub use flows::EtwFlows;

#[cfg(windows)]
mod sensor;
#[cfg(windows)]
pub use sensor::EtwSensor;
