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

use scribe_core::{Alert, Clock, FlowKind, Notes, Observation, Protocol, Security};
use scribe_enrich::quic::Progress;
use scribe_enrich::{Enricher, InitialReassembler};
use scribe_policy::{alert_key, Policy};
use scribe_storage_api::{
    AlertRecord, AlertState, AuditRecord, BaselineEntry, EntrySource, HostDelta, StateStore,
    StorageError, StoredEvent,
};
use serde_json::json;

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
    /// Earlier alerts that gained notes (the URL of a later request) inside the dedupe window.
    /// They are not stored or sent again; the API shows them from phase 10.
    pub alert_updates: Vec<Alert>,
    /// Module signal reasons the hooks returned (for metrics and tests).
    pub signals: Vec<String>,
}

impl Writes {
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
            && self.hosts.is_empty()
            && self.baseline.is_empty()
            && self.alert_states.is_empty()
            && self.alerts.is_empty()
            && self.alert_updates.is_empty()
    }

    fn extend(&mut self, other: Writes) {
        self.events.extend(other.events);
        self.hosts.extend(other.hosts);
        self.baseline.extend(other.baseline);
        self.alert_states.extend(other.alert_states);
        self.alerts.extend(other.alerts);
        self.alert_updates.extend(other.alert_updates);
        self.signals.extend(other.signals);
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
    /// Observations that arrived while hibernating (not recorded).
    pub dropped_hibernating: u64,
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
            dropped_hibernating: 0,
        }
    }
}

/// The daemon's run state (specs 8.5); `degraded` is a health result, not a state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonState {
    Running,
    Hibernating {
        since: SystemTime,
        /// When it wakes up on its own; `None` only with an unlimited `daemon.max_hibernate`.
        until: Option<SystemTime>,
        caller: String,
    },
}

impl DaemonState {
    pub fn name(&self) -> &'static str {
        match self {
            DaemonState::Running => "running",
            DaemonState::Hibernating { .. } => "hibernating",
        }
    }
}

/// What `scribe daemon status` reports from the pipeline (the API adds storage and sensor parts).
#[derive(Debug, Clone)]
pub struct Status {
    pub state: DaemonState,
    pub mode: scribe_core::Mode,
    pub learn_until: Option<SystemTime>,
    pub profile: String,
    pub counters: RuntimeCounters,
    pub held_quic: usize,
    pub dns_entries: usize,
    pub modules: Vec<crate::modules::ModuleStatus>,
}

/// The address daemon alerts (`hibernated`) carry: they have no destination.
pub const NO_DESTINATION: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

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
    state: DaemonState,
    max_hibernate: Option<Duration>,
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
            state: DaemonState::Running,
            max_hibernate: Some(Duration::from_secs(4 * 3600)),
        }
    }

    /// The cap for hibernation (`daemon.max_hibernate`); `None` = unlimited.
    pub fn with_max_hibernate(mut self, max: Option<Duration>) -> Self {
        self.max_hibernate = max;
        self
    }

    pub fn set_max_hibernate(&mut self, max: Option<Duration>) {
        self.max_hibernate = max;
    }

    /// Another baseline profile (config reload); the caller loads its baseline into the policy.
    pub fn set_profile(&mut self, profile: impl Into<String>) {
        self.profile = profile.into();
    }

    pub fn state(&self) -> &DaemonState {
        &self.state
    }

    pub fn is_hibernating(&self) -> bool {
        matches!(self.state, DaemonState::Hibernating { .. })
    }

    pub fn status(&self) -> Status {
        Status {
            state: self.state.clone(),
            mode: self.policy.mode(),
            learn_until: self.policy.learn_until(),
            profile: self.profile.clone(),
            counters: self.counters.clone(),
            held_quic: self.held.len(),
            dns_entries: self.enricher.dns().len(),
            modules: self.modules.status(),
        }
    }

    /// Stop processing (specs 8.5): held flows are judged first, modules pause, the learn
    /// countdown stops; an `audit` event and a `hibernated` alert are written. The caller stops
    /// the sensor. `for_` is capped by `daemon.max_hibernate`; without it the cap applies. Calling
    /// it again while hibernating sets a new end (still capped) and writes only an audit event.
    pub fn hibernate(&mut self, for_: Option<Duration>, caller: &str) -> Writes {
        let now = self.clock.now();
        let length = match (for_, self.max_hibernate) {
            (Some(d), Some(max)) => Some(d.min(max)),
            (Some(d), None) => Some(d),
            (None, max) => max,
        };
        let until = length.map(|d| now + d);
        let mut w = Writes::default();
        if let DaemonState::Hibernating {
            since,
            caller: first,
            ..
        } = &self.state
        {
            self.state = DaemonState::Hibernating {
                since: *since,
                until,
                caller: first.clone(),
            };
            w.events.push(audit(
                now,
                format!("hibernate extended by {caller} until {}", when(until)),
            ));
            return w;
        }
        w.extend(self.flush());
        self.modules.pause();
        self.policy.pause_learn_timer();
        self.state = DaemonState::Hibernating {
            since: now,
            until,
            caller: caller.to_owned(),
        };
        w.events.push(audit(
            now,
            format!("hibernate by {caller} until {}", when(until)),
        ));
        let mut notes = Notes::new();
        notes.insert(
            "daemon",
            json!({ "caller": caller, "until": until.map(humantime_rfc3339) }),
        );
        let alert = Alert {
            ts: now,
            host: None,
            dst_ip: NO_DESTINATION,
            dst_port: 0,
            process_path: None,
            score: 100,
            reason: "hibernated".into(),
            notes,
        };
        self.counters.alerts += 1;
        w.events.push(StoredEvent::Alert(AlertRecord::from(&alert)));
        w.alerts.push(alert);
        w
    }

    /// Resume processing with the same mode, baseline and caches; the caller starts the sensor.
    pub fn wakeup(&mut self, caller: &str) -> Writes {
        let mut w = Writes::default();
        if !self.is_hibernating() {
            return w;
        }
        self.state = DaemonState::Running;
        self.modules.resume();
        self.policy.resume_learn_timer();
        w.events
            .push(audit(self.clock.now(), format!("wakeup by {caller}")));
        w
    }

    /// Whether a hibernation has reached its end ([`Pipeline::tick`] wakes it).
    pub fn wakeup_due(&self) -> bool {
        matches!(&self.state, DaemonState::Hibernating { until: Some(u), .. } if self.clock.now() >= *u)
    }

    /// Empty the DNS cache (`reset --caches`; the caller also clears the storage cache).
    pub fn clear_caches(&mut self) {
        self.enricher.clear_dns();
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
        if self.is_hibernating() {
            self.counters.dropped_hibernating += 1;
            return Writes::default();
        }
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

    /// Judge held QUIC flows whose time ran out and end a hibernation that reached its end.
    /// Call about once a second; check [`Pipeline::state`] afterwards to restart the sensor.
    pub fn tick(&mut self) -> Writes {
        if self.wakeup_due() {
            return self.wakeup("timer");
        }
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
        w.signals = reasons;
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
                unresolved: event.unresolved(),
                process: event.process_path.clone(),
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
        if let Some(updated) = d.alert_update {
            w.alert_updates.push(updated);
        }
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

fn audit(ts: SystemTime, message: String) -> StoredEvent {
    StoredEvent::Audit(AuditRecord { ts, message })
}

fn when(until: Option<SystemTime>) -> String {
    until.map_or_else(|| "it is woken up".to_owned(), humantime_rfc3339)
}

/// `2026-11-22T10:00:00Z` (UTC, whole seconds).
pub fn humantime_rfc3339(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = secs / 86_400;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}
