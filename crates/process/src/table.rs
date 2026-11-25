use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use scribe_core::Clock;

/// Shortest time between two reads of the socket table; misses in between wait for the next.
pub const MIN_REFRESH: Duration = Duration::from_millis(100);
/// A read of the table that takes longer than this is slow: the next read waits
/// [`SLOW_FACTOR`] times as long as it took (at most [`MAX_REFRESH`]), so scanning a busy
/// system stays around a tenth of one core at worst.
pub const SCAN_BUDGET: Duration = Duration::from_millis(50);
pub const SLOW_FACTOR: u32 = 10;
/// Longest wait between two reads after slow ones.
pub const MAX_REFRESH: Duration = Duration::from_secs(5);

/// Reads of the socket table and how long they took.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanStats {
    pub scans: u64,
    /// Reads over [`SCAN_BUDGET`].
    pub slow: u64,
    pub last: Duration,
    pub max: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
}

/// One socket and its owner, as the OS table lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    pub transport: Transport,
    pub local: SocketAddr,
    /// `None` for an unconnected UDP socket (and listening TCP sockets, which are skipped).
    pub remote: Option<SocketAddr>,
    pub pid: u32,
}

/// The process that owns a flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub pid: u32,
    /// `None` when the path can't be read (the process ended, or no permission).
    pub path: Option<String>,
}

/// The OS socket table (or a test double).
pub trait SocketTable: Send {
    /// Every TCP and UDP socket with its owning process, listening TCP sockets left out.
    fn snapshot(&mut self) -> io::Result<Vec<SocketEntry>>;
    /// The executable of `pid`.
    fn process_path(&self, pid: u32) -> Option<String>;
}

/// IPv4-mapped IPv6 addresses as IPv4, so both kinds of table entries match one flow.
pub fn normalise(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

/// Finds the owner of a flow in a cached copy of the socket table, reading it again on a miss
/// (at most every [`MIN_REFRESH`]).
pub struct Resolver {
    table: Box<dyn SocketTable>,
    clock: Arc<dyn Clock>,
    /// (transport, local, remote) → pid; remote `None` for unconnected UDP.
    exact: HashMap<(Transport, SocketAddr, Option<SocketAddr>), u32>,
    /// (transport, local port) → pid, for sockets bound to a wildcard or another local address.
    by_port: HashMap<(Transport, u16), u32>,
    paths: HashMap<u32, Option<String>>,
    read_at: Option<SystemTime>,
    /// Wait before the next read: [`MIN_REFRESH`], longer after a slow read.
    gap: Duration,
    scans: ScanStats,
    failing: bool,
}

impl Resolver {
    pub fn new(table: Box<dyn SocketTable>, clock: Arc<dyn Clock>) -> Self {
        Self {
            table,
            clock,
            exact: HashMap::new(),
            by_port: HashMap::new(),
            paths: HashMap::new(),
            read_at: None,
            gap: MIN_REFRESH,
            scans: ScanStats::default(),
            failing: false,
        }
    }

    fn find(&self, transport: Transport, local: SocketAddr, remote: SocketAddr) -> Option<u32> {
        let (local, remote) = (normalise(local), normalise(remote));
        self.exact
            .get(&(transport, local, Some(remote)))
            .or_else(|| self.exact.get(&(transport, local, None)))
            .or_else(|| self.by_port.get(&(transport, local.port())))
            .copied()
    }

    /// How often the table was read and how long that took.
    pub fn scan_stats(&self) -> ScanStats {
        self.scans
    }

    /// Wait before the next read of the table.
    pub fn refresh_gap(&self) -> Duration {
        self.gap
    }

    fn refresh(&mut self, now: SystemTime) {
        self.read_at = Some(now);
        let snapshot = self.table.snapshot();
        let took = self.clock.now().duration_since(now).unwrap_or_default();
        self.time_scan(took);
        match snapshot {
            Ok(entries) => {
                self.failing = false;
                self.exact.clear();
                self.by_port.clear();
                // Paths are read again for the pids of this table: a pid can be reused.
                self.paths.clear();
                for e in entries {
                    let local = normalise(e.local);
                    let remote = e.remote.map(normalise);
                    self.exact.insert((e.transport, local, remote), e.pid);
                    self.by_port
                        .entry((e.transport, local.port()))
                        .or_insert(e.pid);
                }
            }
            Err(e) => {
                if !self.failing {
                    tracing::warn!("cannot read the socket table for process attribution: {e}");
                }
                self.failing = true;
            }
        }
    }

    fn time_scan(&mut self, took: Duration) {
        let s = &mut self.scans;
        s.scans += 1;
        s.last = took;
        s.max = s.max.max(took);
        if took > SCAN_BUDGET {
            s.slow += 1;
            let gap = (took * SLOW_FACTOR).clamp(MIN_REFRESH, MAX_REFRESH);
            if s.slow == 1 {
                tracing::warn!(
                    "reading the socket table took {} ms (budget {} ms); reading it at most every {} ms",
                    took.as_millis(),
                    SCAN_BUDGET.as_millis(),
                    gap.as_millis()
                );
            }
            self.gap = gap;
        } else {
            self.gap = MIN_REFRESH;
        }
    }

    /// The owner of the flow from `local` to `remote`, if its socket is still open.
    pub fn lookup(
        &mut self,
        transport: Transport,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<Owner> {
        let pid = match self.find(transport, local, remote) {
            Some(pid) => pid,
            None => {
                let now = self.clock.now();
                let stale = self
                    .read_at
                    .is_none_or(|at| now.duration_since(at).unwrap_or_default() >= self.gap);
                if !stale {
                    return None;
                }
                self.refresh(now);
                self.find(transport, local, remote)?
            }
        };
        let table = &self.table;
        let path = self
            .paths
            .entry(pid)
            .or_insert_with(|| table.process_path(pid))
            .clone();
        Some(Owner { pid, path })
    }
}
