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
//! [`Owners`] joins them by address, so every flow gets its process from the kernel, even one
//! that ends at once. [`record`] and [`owners`] build on every system (their tests run
//! everywhere); the loader is Linux only.

pub mod owners;
pub mod record;

pub use owners::{ExePath, Owner, Owners, MAX_OWNERS, OWNER_TTL};
pub use record::{Record, RecordError, RecordKind, RECORD_SIZE, RECORD_VERSION};

#[cfg(target_os = "linux")]
mod sensor;
#[cfg(target_os = "linux")]
pub use sensor::EbpfSensor;
