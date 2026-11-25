//! Process attribution from the operating system's socket tables (plan option P).
//!
//! The pcap sensor sees packets but not which program sent them. Every system keeps a table of
//! open sockets with their owner, so for each new flow [`Resolver`] looks up the socket with the
//! flow's addresses and ports and reports its process id and executable path:
//!
//! | System | Socket table | Executable path |
//! |---|---|---|
//! | Linux | `/proc/net/{tcp,tcp6,udp,udp6}` (socket inode) and `/proc/<pid>/fd` (inode → pid) | `/proc/<pid>/exe` |
//! | macOS | `libproc`: every process's socket descriptors (`PROC_PIDFDSOCKETINFO`) | `proc_pidpath` |
//! | Windows | IP Helper `GetExtendedTcpTable` / `GetExtendedUdpTable` with the owning pid | `QueryFullProcessImageNameW` |
//!
//! Reading the table of other users' processes needs root / Administrator, as capture does.
//! A connection that ends before the lookup, or a UDP socket closed right after one datagram, is
//! not found: the flow keeps no process, as before. [`Attributed`] wraps a sensor and fills in
//! the process of its observations.
//!
//! Native sensors (eBPF on Linux, ETW on Windows) report each connection with its process
//! themselves; [`join`] matches those reports with the observations built from packets.

mod attributed;
pub mod join;
mod os;
mod table;

pub use attributed::Attributed;
pub use os::{os_table, parse_proc_net, ProcNetEntry};
pub use scribe_core::AttributionStats;
pub use table::{
    normalise, Owner, Resolver, ScanStats, SocketEntry, SocketTable, Transport, MAX_REFRESH,
    MIN_REFRESH, SCAN_BUDGET, SLOW_FACTOR,
};
