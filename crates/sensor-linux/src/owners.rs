//! Joins the kernel's connection records (who) with the observations built from packets (what).
//!
//! A `tcp_connect` record arrives before the connection's first packet leaves, a `udp_sendmsg`
//! record before its datagram: the owner is known by the time the flow tracker reports the flow.
//! Entries are found by the exact local and remote address, then by local port and remote address
//! (an unconnected UDP socket reports `0.0.0.0` as its local address). They stay while the flow is
//! in use and are dropped [`OWNER_TTL`] after the last record or match, or when the table is full.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use scribe_core::{Clock, Observation, Protocol};
use scribe_process::{normalise, Transport};

use crate::record::Record;

/// How long an owner is kept after its last record or match.
pub const OWNER_TTL: Duration = Duration::from_secs(600);
/// Most owners kept; the least recently used ones go first.
pub const MAX_OWNERS: usize = 65_536;

/// Reads a process's executable path (`/proc/<pid>/exe` on Linux).
pub type ExePath = Box<dyn Fn(u32) -> Option<String> + Send>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    /// `None` when the process ended before scribed read it.
    pub path: Option<String>,
    seen: SystemTime,
}

type Exact = (Transport, SocketAddr, SocketAddr);
type ByPort = (Transport, u16, SocketAddr);

pub struct Owners {
    clock: Arc<dyn Clock>,
    exe: ExePath,
    exact: HashMap<Exact, Owner>,
    by_port: HashMap<ByPort, Exact>,
    /// Paths read for each process, so a busy process isn't read on every record.
    paths: HashMap<u32, (Option<String>, SystemTime)>,
    swept: Option<SystemTime>,
}

/// How often old entries are looked for.
const SWEEP_EVERY: Duration = Duration::from_secs(10);

/// How long a process's path is reused before it is read again (a pid can be reused).
const PATH_TTL: Duration = Duration::from_secs(5);

fn transport(proto: Protocol) -> Transport {
    match proto {
        Protocol::Tcp => Transport::Tcp,
        Protocol::Udp | Protocol::Quic => Transport::Udp,
    }
}

impl Owners {
    pub fn new(clock: Arc<dyn Clock>, exe: ExePath) -> Self {
        Self {
            clock,
            exe,
            exact: HashMap::new(),
            by_port: HashMap::new(),
            paths: HashMap::new(),
            swept: None,
        }
    }

    pub fn len(&self) -> usize {
        self.exact.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
    }

    fn path(&mut self, pid: u32, now: SystemTime) -> Option<String> {
        if let Some((path, at)) = self.paths.get(&pid) {
            if now.duration_since(*at).unwrap_or_default() < PATH_TTL {
                return path.clone();
            }
        }
        let path = (self.exe)(pid);
        self.paths.insert(pid, (path.clone(), now));
        path
    }

    /// Takes in one record from the kernel.
    pub fn record(&mut self, r: &Record) {
        let now = self.clock.now();
        self.expire(now);
        if self.exact.len() >= MAX_OWNERS {
            self.evict_oldest();
        }
        let path = self.path(r.tgid, now);
        let key = (r.kind.transport(), r.src, r.dst);
        self.exact.insert(
            key,
            Owner {
                pid: r.tgid,
                uid: r.uid,
                comm: r.comm.clone(),
                path,
                seen: now,
            },
        );
        self.by_port
            .insert((r.kind.transport(), r.src.port(), r.dst), key);
    }

    /// The owner of the flow from `src` to `dst`, if a record named it.
    pub fn lookup(
        &mut self,
        transport: Transport,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Option<&Owner> {
        let (src, dst) = (normalise(src), normalise(dst));
        let now = self.clock.now();
        let key = if self.exact.contains_key(&(transport, src, dst)) {
            (transport, src, dst)
        } else {
            *self.by_port.get(&(transport, src.port(), dst))?
        };
        let owner = self.exact.get_mut(&key)?;
        owner.seen = now;
        Some(owner)
    }

    /// Fills in the process of an observation that has none. Returns whether it had or got one.
    pub fn attribute(&mut self, obs: &mut Observation) -> bool {
        let e = &mut obs.event;
        if e.pid.is_some() {
            return true;
        }
        let dst = SocketAddr::new(e.dst_ip, e.dst_port);
        match self.lookup(transport(e.proto), e.src, dst) {
            Some(owner) => {
                e.pid = Some(owner.pid);
                e.process_path = owner.path.clone();
                true
            }
            None => false,
        }
    }

    /// Drops old entries, at most every [`SWEEP_EVERY`].
    fn expire(&mut self, now: SystemTime) {
        if self
            .swept
            .is_some_and(|at| now.duration_since(at).unwrap_or_default() < SWEEP_EVERY)
        {
            return;
        }
        self.swept = Some(now);
        let before = self.exact.len();
        self.exact
            .retain(|_, o| now.duration_since(o.seen).unwrap_or_default() < OWNER_TTL);
        if self.exact.len() != before {
            let exact = &self.exact;
            self.by_port.retain(|_, k| exact.contains_key(k));
            self.paths
                .retain(|_, (_, at)| now.duration_since(*at).unwrap_or_default() < PATH_TTL);
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest) = self
            .exact
            .iter()
            .min_by_key(|(_, o)| o.seen)
            .map(|(k, _)| *k)
        {
            self.exact.remove(&oldest);
            self.by_port.retain(|_, k| *k != oldest);
        }
    }
}
