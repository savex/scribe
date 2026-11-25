//! Holds packet observations whose owner hasn't been reported yet.
//!
//! A `tcp_connect` record is written before the connection's SYN leaves, but a UDP record comes
//! from `fexit/udp_sendmsg`, after the datagram is sent, so the packet can reach scribed first.
//! Observations without an owner wait up to [`HOLD`] for their record, in arrival order (a later
//! observation never overtakes an earlier one), then go out with or without a process.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use scribe_core::{AttributionStats, Clock, FlowKind, Observation};

use crate::owners::Owners;
use crate::record::Record;

/// Longest wait for a connection record.
pub const HOLD: Duration = Duration::from_millis(100);

pub struct Joiner {
    owners: Owners,
    clock: Arc<dyn Clock>,
    held: VecDeque<(Observation, SystemTime)>,
    attributed: u64,
    missed: u64,
}

impl Joiner {
    pub fn new(owners: Owners, clock: Arc<dyn Clock>) -> Self {
        Self {
            owners,
            clock,
            held: VecDeque::new(),
            attributed: 0,
            missed: 0,
        }
    }

    /// A record from the kernel.
    pub fn record(&mut self, r: &Record) {
        self.owners.record(r);
    }

    /// New observations from the flow tracker; returns those ready to send, in order.
    pub fn push(&mut self, observations: Vec<Observation>) -> Vec<Observation> {
        let now = self.clock.now();
        self.held
            .extend(observations.into_iter().map(|obs| (obs, now)));
        self.release(false)
    }

    /// Sends what found its owner or waited long enough (call after reading records).
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
            let waited = now.duration_since(*since).unwrap_or_default() >= HOLD;
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
