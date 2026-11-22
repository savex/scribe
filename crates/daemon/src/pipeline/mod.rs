//! The capture pipeline (specs 7.1): sensor observations → enrichment → modules → policy →
//! storage writes and alerts.
//!
//! [`Pipeline::process`] is synchronous and does no I/O: it returns the [`Writes`] for one
//! observation, which [`store`] then applies to storage. That keeps every decision testable with
//! `FakeClock` and in-memory doubles.
//!
//! QUIC: a client Initial whose ClientHello needs more datagrams is **held** (not judged yet) until
//! the hello is complete, the flow closes, or [`QUIC_HOLD`] passes ([`Pipeline::tick`]); judging
//! it early would report a named QUIC flow as a raw IP.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use scribe_core::{Alert, Clock, FlowKind, Observation, Protocol, Security};
use scribe_enrich::quic::Progress;
use scribe_enrich::{Enricher, InitialReassembler};
use scribe_policy::{alert_key, Policy};
use scribe_storage_api::{
    AlertRecord, AlertState, BaselineEntry, EntrySource, HostDelta, StateStore, StorageError,
    StoredEvent,
};

use crate::modules::ModuleHost;

/// How long a QUIC flow waits for the rest of its ClientHello.
pub const QUIC_HOLD: Duration = Duration::from_secs(1);
/// QUIC flows held at once; the oldest is judged when a new one would pass the limit.
pub const QUIC_HELD_MAX: usize = 1024;

/// What one observation (or a tick) changes. Applied by [`store`].
#[derive(Debug, Default)]
pub struct Writes {
    /// Flow and alert events for the event sinks.
    pub events: Vec<StoredEvent>,
    /// Host counter deltas for the state store.
    pub hosts: Vec<HostDelta>,
    /// Hosts learned in learn mode.
    pub baseline: Vec<BaselineEntry>,
    /// Dedupe state of every alert raised.
    pub alert_states: Vec<AlertState>,
    /// Alerts for the alert outputs.
    pub alerts: Vec<Alert>,
}

impl Writes {
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
            && self.hosts.is_empty()
            && self.baseline.is_empty()
            && self.alert_states.is_empty()
            && self.alerts.is_empty()
    }

    fn extend(&mut self, other: Writes) {
        self.events.extend(other.events);
        self.hosts.extend(other.hosts);
        self.baseline.extend(other.baseline);
        self.alert_states.extend(other.alert_states);
        self.alerts.extend(other.alerts);
    }
}

/// Runtime counters behind `scribe daemon status` (specs 8.5.1); never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCounters {
    pub since: SystemTime,
    /// Every observation the sensor delivered.
    pub observations: u64,
    /// Judged new flows.
    pub flows: u64,
    /// Judged payload observations (later requests on a connection).
    pub payloads: u64,
    pub dns_responses: u64,
    pub alerts: u64,
    pub baseline_added: u64,
    /// QUIC flows judged without a complete ClientHello (time or room ran out).
    pub quic_unfinished: u64,
}

impl RuntimeCounters {
    fn new(since: SystemTime) -> Self {
        Self {
            since,
            observations: 0,
            flows: 0,
            payloads: 0,
            dns_responses: 0,
            alerts: 0,
            baseline_added: 0,
            quic_unfinished: 0,
        }
    }
}

struct Held {
    obs: Observation,
    reassembler: InitialReassembler,
    until: SystemTime,
}

type FlowKey = (SocketAddr, SocketAddr);

fn flow_key(obs: &Observation) -> FlowKey {
    (
        obs.event.src,
        SocketAddr::new(obs.event.dst_ip, obs.event.dst_port),
    )
}

pub struct Pipeline {
    clock: Arc<dyn Clock>,
    profile: String,
    enricher: Enricher,
    modules: ModuleHost,
    policy: Policy,
    held: HashMap<FlowKey, Held>,
    counters: RuntimeCounters,
}

impl Pipeline {
    pub fn new(
        clock: Arc<dyn Clock>,
        profile: impl Into<String>,
        enricher: Enricher,
        modules: ModuleHost,
        policy: Policy,
    ) -> Self {
        let counters = RuntimeCounters::new(clock.now());
        Self {
            clock,
            profile: profile.into(),
            enricher,
            modules,
            policy,
            held: HashMap::new(),
            counters,
        }
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn policy_mut(&mut self) -> &mut Policy {
        &mut self.policy
    }

    pub fn modules(&self) -> &ModuleHost {
        &self.modules
    }

    pub fn modules_mut(&mut self) -> &mut ModuleHost {
        &mut self.modules
    }

    pub fn enricher(&self) -> &Enricher {
        &self.enricher
    }

    pub fn counters(&self) -> &RuntimeCounters {
        &self.counters
    }

    /// Zero the runtime counters (`reset --counters`); stored history is untouched.
    pub fn reset_counters(&mut self) {
        self.counters = RuntimeCounters::new(self.clock.now());
    }

    /// QUIC flows waiting for the rest of their ClientHello.
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Handle one sensor observation.
    pub fn process(&mut self, mut obs: Observation) -> Writes {
        self.counters.observations += 1;
        match obs.event.kind {
            FlowKind::DnsResponse => {
                if let Some(msg) = &obs.head {
                    self.enricher.observe_dns_response(msg);
                }
                self.counters.dns_responses += 1;
                return Writes::default();
            }
            FlowKind::Close => {
                let mut w = self.release(&flow_key(&obs));
                w.extend(self.judge(obs));
                return w;
            }
            FlowKind::Payload if self.held.contains_key(&flow_key(&obs)) => {
                return self.continue_quic(obs);
            }
            _ => {}
        }
        self.enricher.enrich(&mut obs);
        if obs.event.kind == FlowKind::NewFlow && self.needs_more_quic(&obs) {
            return self.hold(obs);
        }
        self.judge(obs)
    }

    /// Judge held QUIC flows whose time ran out. Call about once a second.
    pub fn tick(&mut self) -> Writes {
        let now = self.clock.now();
        let expired: Vec<FlowKey> = self
            .held
            .iter()
            .filter(|(_, h)| now >= h.until)
            .map(|(k, _)| *k)
            .collect();
        let mut w = Writes::default();
        for key in expired {
            w.extend(self.release(&key));
        }
        w
    }

    /// Judge every held flow now (shutdown, hibernation).
    pub fn flush(&mut self) -> Writes {
        let keys: Vec<FlowKey> = self.held.keys().copied().collect();
        let mut w = Writes::default();
        for key in keys {
            w.extend(self.release(&key));
        }
        w
    }

    fn needs_more_quic(&self, obs: &Observation) -> bool {
        matches!(obs.event.proto, Protocol::Udp | Protocol::Quic)
            && obs.event.security == Security::Quic
            && obs.event.hostname.is_none()
            && obs
                .head
                .as_deref()
                .is_some_and(|h| scribe_enrich::quic::decrypt_initial(h).is_ok())
    }

    fn hold(&mut self, obs: Observation) -> Writes {
        let mut w = Writes::default();
        if self.held.len() >= QUIC_HELD_MAX {
            if let Some(oldest) = self
                .held
                .iter()
                .min_by_key(|(_, h)| h.until)
                .map(|(k, _)| *k)
            {
                w.extend(self.release(&oldest));
            }
        }
        let mut reassembler = InitialReassembler::default();
        if let Some(head) = &obs.head {
            reassembler.push(head);
        }
        self.held.insert(
            flow_key(&obs),
            Held {
                obs,
                reassembler,
                until: self.clock.now() + QUIC_HOLD,
            },
        );
        w
    }

    fn continue_quic(&mut self, obs: Observation) -> Writes {
        let key = flow_key(&obs);
        let progress = {
            let held = self.held.get_mut(&key).expect("held flow");
            obs.head
                .as_deref()
                .map_or(Progress::NeedMore, |d| held.reassembler.push(d))
        };
        match progress {
            Progress::NeedMore => Writes::default(),
            Progress::Hello(hello) => {
                let mut held = self.held.remove(&key).expect("held flow");
                Enricher::apply_hello(&mut held.obs.event, hello);
                self.judge(held.obs)
            }
            Progress::Failed => self.release(&key),
        }
    }

    fn release(&mut self, key: &FlowKey) -> Writes {
        match self.held.remove(key) {
            Some(held) => {
                self.counters.quic_unfinished += 1;
                self.judge(held.obs)
            }
            None => Writes::default(),
        }
    }

    /// Modules, policy and the writes for one enriched observation.
    fn judge(&mut self, mut obs: Observation) -> Writes {
        let mut w = Writes::default();
        let (notes, signals) = self.modules.on_flow(&obs);
        obs.event.notes.merge(notes);
        let reasons: Vec<String> = signals.into_iter().map(|s| s.reason).collect();
        let d = self.policy.decide(&obs.event, &reasons);
        let event = &obs.event;
        match event.kind {
            FlowKind::NewFlow => self.counters.flows += 1,
            FlowKind::Payload => self.counters.payloads += 1,
            FlowKind::Close | FlowKind::DnsResponse => {}
        }
        if event.kind != FlowKind::Close {
            w.hosts.push(HostDelta {
                name: d.host.clone(),
                seen_at: event.ts,
                connections: u64::from(event.kind == FlowKind::NewFlow),
                requests: u64::from(event.notes.get_str("url").is_some()),
                bytes_out: event.bytes_out,
                security: event.security,
            });
            w.events.push(StoredEvent::Flow(event.clone()));
        }
        if let Some(host) = d.baseline_add {
            self.counters.baseline_added += 1;
            w.baseline.push(BaselineEntry {
                host,
                source: EntrySource::Learned,
                added_at: self.clock.now(),
            });
        }
        if let Some(alert) = d.alert {
            self.counters.alerts += 1;
            w.alert_states.push(AlertState {
                key: alert_key(&alert),
                last_alerted: alert.ts,
                acknowledged: false,
            });
            w.events.push(StoredEvent::Alert(AlertRecord::from(&alert)));
            w.alerts.push(alert);
        }
        // An updated alert (new notes inside the dedupe window) is not stored again: the stored
        // alert keeps the notes it was raised with, and outputs are not notified twice.
        w
    }
}

/// Where [`store`] writes: the running storage manager, or test doubles.
pub trait Store {
    fn publish(&self, events: &[StoredEvent]);
    fn state(&self) -> &dyn StateStore;
}

impl Store for scribe_storage_manager::Storage {
    fn publish(&self, events: &[StoredEvent]) {
        scribe_storage_manager::Storage::publish(self, events);
    }

    fn state(&self) -> &dyn StateStore {
        scribe_storage_manager::Storage::state(self)
    }
}

/// Apply `writes`: events to the sinks (non-blocking), counters, baseline entries and alert state
/// to the state store. Returns the state-store errors; the caller logs them.
pub async fn store(target: &dyn Store, profile: &str, writes: &Writes) -> Vec<StorageError> {
    let mut errors = Vec::new();
    if !writes.events.is_empty() {
        target.publish(&writes.events);
    }
    let state = target.state();
    for delta in &writes.hosts {
        if let Err(e) = state.upsert_host(delta).await {
            errors.push(e);
        }
    }
    for entry in &writes.baseline {
        if let Err(e) = state.add_to_baseline(profile, entry).await {
            errors.push(e);
        }
    }
    for alert in &writes.alert_states {
        if let Err(e) = state.put_alert_state(alert).await {
            errors.push(e);
        }
    }
    errors
}
