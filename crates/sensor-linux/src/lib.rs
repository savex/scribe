//! Linux sensor based on eBPF (plan option 7B): C programs in `src/bpf/*.bpf.c` (CO-RE), loaded
//! with `libbpf-rs`.
//!
//! Two parts meet in user space:
//! - **who**: kprobes on `tcp_connect` and `udp_sendmsg` / `udpv6_sendmsg` write a [`Record`]
//!   (process, thread, user, cgroup and the connection's addresses) to a ring buffer when a
//!   process opens a connection or sends a datagram;
//! - **what**: a socket filter on an `AF_PACKET` socket passes outgoing packets and DNS answers,
//!   cut to what enrichment needs, to the pcap sensor's flow tracker (first bytes, DNS, QUIC,
//!   closes).
//!
//! `scribe_process::join` joins them by address, so every flow gets its process from the kernel,
//! even one that ends at once; observations wait up to [`HOLD`] for a record that is late (UDP
//! records are written after the datagram leaves). [`record`] builds on every system (its tests
//! run everywhere); the loader is Linux only.

use std::time::Duration;

pub mod record;

/// Longest wait for a connection record.
pub const HOLD: Duration = Duration::from_millis(100);

pub use record::{Record, RecordError, RecordKind, PATH_MAX, RECORD_SIZE, RECORD_VERSION};

#[cfg(target_os = "linux")]
mod sensor;
#[cfg(target_os = "linux")]
pub use sensor::EbpfSensor;
