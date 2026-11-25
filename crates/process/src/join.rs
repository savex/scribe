//! Joins a native sensor's connection reports (who: process and addresses, from eBPF or ETW) with
//! the observations built from packets (what: first bytes, DNS, closes).
//!
//! A report usually arrives before the flow's first packet is seen, but not always (a UDP report
//! from `fexit/udp_sendmsg` comes after the datagram; ETW delivers in batches). [`Owners`] keeps
//! the owner of each connection, found by the exact local and remote address, then by local port
//! and remote address (an unconnected UDP socket reports `0.0.0.0` as its local address), dropped
//! [`OWNER_TTL`] after the last report or match, or when the table is full. [`Joiner`] holds
//! observations without an owner for a while, in arrival order (a later one never overtakes an
//! earlier one), then sends them with or without a process.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use scribe_core::{AttributionStats, Clock, FlowKind, Observation, Protocol};

use crate::table::{normalise, Transport};

/// How long an owner is kept after its last record or match.
pub const OWNER_TTL: Duration = Duration::from_secs(600);
/// Most owners kept; the least recently used ones go first.
pub const MAX_OWNERS: usize = 65_536;

/// Reads a process's executable path (`/proc/<pid>/exe`, `QueryFullProcessImageNameW`), for
/// connections reported without one.
pub type ExePath = Box<dyn Fn(u32) -> Option<String> + Send>;

/// A connection as a native sensor reports it, with the process that made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub transport: Transport,
    /// Local address; `0.0.0.0` / `::` for a UDP socket not bound to one address.
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub pid: u32,
    pub uid: Option<u32>,
    /// The process's (or thread's) short name, where the source has one.
    pub name: Option<String>,
    /// The executable when the source reports it (eBPF); else read through [`ExePath`].
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub pid: u32,
    pub uid: Option<u32>,
    pub name: Option<String>,
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

    /// Takes in one connection report.
    pub fn record(&mut self, c: &Connection) {
        let now = self.clock.now();
        self.expire(now);
        if self.exact.len() >= MAX_OWNERS {
            self.evict_oldest();
        }
        // A path from the source needs no rights over the process; ExePath is the fallback.
        let path = match &c.path {
            Some(p) => Some(p.clone()),
            None => self.path(c.pid, now),
        };
        let (src, dst) = (normalise(c.src), normalise(c.dst));
        let key = (c.transport, src, dst);
        self.exact.insert(
            key,
            Owner {
                pid: c.pid,
                uid: c.uid,
                name: c.name.clone(),
                path,
                seen: now,
            },
        );
        self.by_port.insert((c.transport, src.port(), dst), key);
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

/// Holds packet observations whose connection report hasn't arrived yet.
pub struct Joiner {
    owners: Owners,
    clock: Arc<dyn Clock>,
    hold: Duration,
    held: VecDeque<(Observation, SystemTime)>,
    attributed: u64,
    missed: u64,
}

impl Joiner {
    /// `hold`: the longest an observation waits for its connection report.
    pub fn new(owners: Owners, clock: Arc<dyn Clock>, hold: Duration) -> Self {
        Self {
            owners,
            clock,
            hold,
            held: VecDeque::new(),
            attributed: 0,
            missed: 0,
        }
    }

    /// A connection report from the sensor.
    pub fn record(&mut self, c: &Connection) {
        self.owners.record(c);
    }

    /// New observations from the flow tracker; returns those ready to send, in order.
    pub fn push(&mut self, observations: Vec<Observation>) -> Vec<Observation> {
        let now = self.clock.now();
        self.held
            .extend(observations.into_iter().map(|obs| (obs, now)));
        self.release(false)
    }

    /// Sends what found its owner or waited long enough (call after reading reports).
    pub fn ready(&mut self) -> Vec<Observation> {
        self.release(false)
    }

    /// Everything held, owner or not (at stop).
    pub fn flush(&mut self) -> Vec<Observation> {
        self.release(true)
    }

    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// New flows with and without a process so far.
    pub fn stats(&self) -> AttributionStats {
        AttributionStats {
            attributed: self.attributed,
            missed: self.missed,
            ..AttributionStats::default()
        }
    }

    fn release(&mut self, all: bool) -> Vec<Observation> {
        let now = self.clock.now();
        let mut out = Vec::new();
        while let Some((obs, since)) = self.held.front_mut() {
            // DNS answers are not flows: they never get a process.
            let found = obs.event.kind == FlowKind::DnsResponse || self.owners.attribute(obs);
            let waited = now.duration_since(*since).unwrap_or_default() >= self.hold;
            if !(found || waited || all) {
                break;
            }
            let (obs, _) = self.held.pop_front().expect("front exists");
            if obs.event.kind == FlowKind::NewFlow {
                if obs.event.pid.is_some() {
                    self.attributed += 1;
                } else {
                    self.missed += 1;
                }
            }
            out.push(obs);
        }
        out
    }
}
