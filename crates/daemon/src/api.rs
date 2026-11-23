//! The daemon side of the local API (specs 6.3): the `Scribe` gRPC service and `grpc.health.v1`.
//!
//! Pipeline state comes from the main loop through [`Command::Describe`]; storage is read directly
//! (it is shared with the loop), so listing hosts or alerts never holds up capture.
//! Control calls (mode, ack, baseline edits, reset, hibernate, wakeup) need root or the admin
//! group; each one, and each refusal, is logged and stored as an `audit` event.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scribe_api::access::{Access, AccessPolicy};
use scribe_api::pb;
use scribe_api::pb::scribe_server::Scribe;
use scribe_storage_api::{
    AlertRecord, EntrySource, EventKind, EventQuery, Health, Host, HostQuery, StorageError,
    StoredEvent,
};
use scribe_storage_manager::{SinkStatus, StateStatus, Storage, StorageHealth};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status as RpcStatus};
use tracing::{info, warn};

use crate::app::Command;
use crate::config::Settings;
use crate::modules::RunState;
use crate::pipeline::{DaemonState, Status};

/// How long a call waits for the main loop before reporting it stuck.
pub const LOOP_TIMEOUT: Duration = Duration::from_secs(2);
/// New alerts kept for slow `WatchAlerts` clients; older ones are skipped.
pub const ALERT_BACKLOG: usize = 256;
/// Hosts read from the state store per page while exporting.
const EXPORT_PAGE: usize = 500;
/// Spool or buffer use above this share of its limit is a critical metric.
const HIGH_WATER: f64 = 0.8;
/// How often `grpc.health.v1` is brought up to date.
const HEALTH_EVERY: Duration = Duration::from_secs(2);

/// What the main loop knows: the pipeline status plus sensor, config and rate details.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub status: Status,
    pub sensor: SensorInfo,
    pub started: SystemTime,
    pub now: SystemTime,
    pub config_path: String,
    pub config_loaded: SystemTime,
    pub flows_per_s: f64,
    pub events_per_s: f64,
    /// Module output dropped because the queue was full, per module.
    pub module_drops: BTreeMap<String, u64>,
    /// Modules built into this `scribed`, enabled or not.
    pub modules_built: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorInfo {
    pub name: String,
    pub process_info: bool,
    /// Started and not stopped (false while hibernating or when it could not start).
    pub capturing: bool,
    /// Running without process info on a system that has a native sensor.
    pub fallback: bool,
}

/// Storage parts of the status, read without the main loop.
#[derive(Debug, Clone)]
pub struct StorageView {
    pub health: StorageHealth,
    pub sinks: Vec<SinkStatus>,
    pub state: StateStatus,
}

impl StorageView {
    pub async fn read(storage: &Storage) -> Self {
        Self {
            health: storage.health().await,
            sinks: storage.sink_status(),
            state: storage.state_status(),
        }
    }
}

/// The parts of the settings the API reports; fixed until a restart.
#[derive(Debug, Clone)]
pub struct Layout {
    pub state_kind: String,
    /// Sink name → backend kind.
    pub sink_kinds: Vec<(String, String)>,
    pub spool_max_size: u64,
    pub buffer_events: u64,
}

impl Layout {
    pub fn of(settings: &Settings) -> Self {
        Self {
            state_kind: settings.storage.state.kind.clone(),
            sink_kinds: settings
                .storage
                .sinks
                .iter()
                .map(|s| (s.name.clone(), s.backend.kind.clone()))
                .collect(),
            spool_max_size: settings.limits.spool_max_size,
            buffer_events: settings.limits.buffer_events,
        }
    }
}

pub fn epoch_ms(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

fn from_ms(ms: i64) -> SystemTime {
    if ms >= 0 {
        UNIX_EPOCH + Duration::from_millis(ms as u64)
    } else {
        UNIX_EPOCH - Duration::from_millis(ms.unsigned_abs())
    }
}

fn health_name(h: &Health) -> (&'static str, String) {
    match h {
        Health::Ok => ("ok", String::new()),
        Health::Degraded(why) => ("degraded", why.clone()),
        Health::Down(why) => ("down", why.clone()),
    }
}

fn run_state_name(state: &RunState) -> &'static str {
    match state {
        RunState::Configured => "configured",
        RunState::Running => "running",
        RunState::Paused => "paused",
        RunState::Failed(_) => "failed",
        RunState::Stopped => "stopped",
    }
}

/// Everything dropped that should have been kept: sink queue and write failures, spool overflow,
/// the state-store buffer and module output. Observations seen while hibernating aren't drops.
fn total_drops(snap: &Snapshot, view: &StorageView) -> u64 {
    let sinks: u64 = view
        .sinks
        .iter()
        .map(|s| s.dropped_queue_full + s.dropped_write_failed + s.spool_dropped)
        .sum();
    sinks + view.state.dropped + snap.module_drops.values().sum::<u64>()
}

/// The metrics that need attention (specs 6.2.1), most serious first.
pub fn critical(snap: &Snapshot, view: &StorageView, layout: &Layout) -> Vec<pb::Critical> {
    let mut out = Vec::new();
    let mut add = |kind: &str, detail: String| {
        out.push(pb::Critical {
            kind: kind.into(),
            detail,
        })
    };
    let hibernating = matches!(snap.status.state, DaemonState::Hibernating { .. });
    if !snap.sensor.capturing && !hibernating {
        add(
            "sensor_detached",
            format!("{} sensor is not capturing", snap.sensor.name),
        );
    }
    if let Health::Down(why) = &view.health.state {
        add("state_unhealthy", format!("state store: {why}"));
    }
    for (name, health) in &view.health.sinks {
        if let Health::Down(why) = health {
            add("sink_unhealthy", format!("{name}: {why}"));
        }
    }
    let drops = total_drops(snap, view);
    if drops > 0 {
        add("drops", format!("{drops} records dropped since start"));
    }
    for s in &view.sinks {
        if s.spool_events > 0 {
            add(
                "sink_spooling",
                format!("{}: spooling {} events", s.name, s.spool_events),
            );
        }
    }
    let spooled: u64 = view.sinks.iter().map(|s| s.spool_bytes).sum();
    if layout.spool_max_size > 0 && spooled as f64 > HIGH_WATER * layout.spool_max_size as f64 {
        add(
            "spool_high",
            format!("spool holds {spooled} of {} bytes", layout.spool_max_size),
        );
    }
    if view.state.buffered > 0 {
        add(
            "state_buffering",
            format!("state store buffering {} writes", view.state.buffered),
        );
        if layout.buffer_events > 0
            && view.state.buffered as f64 > HIGH_WATER * layout.buffer_events as f64
        {
            add(
                "buffer_high",
                format!(
                    "state buffer holds {} of {} writes",
                    view.state.buffered, layout.buffer_events
                ),
            );
        }
    }
    if snap.sensor.fallback {
        add(
            "fallback_sensor",
            format!("{} sensor in use: no process info", snap.sensor.name),
        );
    }
    for m in &snap.status.modules {
        if let RunState::Failed(why) = &m.state {
            add("module_failed", format!("{}: {why}", m.id));
        }
    }
    if let DaemonState::Hibernating { since, until, .. } = &snap.status.state {
        let until = until.map_or_else(
            || "someone wakes it up".to_owned(),
            crate::pipeline::humantime_rfc3339,
        );
        add(
            "hibernating",
            format!(
                "hibernating since {} until {until}",
                crate::pipeline::humantime_rfc3339(*since)
            ),
        );
    }
    out
}

/// `GetStatus` from the loop's snapshot and the storage view.
pub fn status_message(snap: &Snapshot, view: &StorageView, layout: &Layout) -> pb::Status {
    let s = &snap.status;
    let (since, until, by) = match &s.state {
        DaemonState::Running => (None, None, String::new()),
        DaemonState::Hibernating {
            since,
            until,
            caller,
        } => (Some(epoch_ms(*since)), until.map(epoch_ms), caller.clone()),
    };
    let (state_health, state_detail) = health_name(&view.health.state);
    let sink_health: HashMap<&str, &Health> = view
        .health
        .sinks
        .iter()
        .map(|(n, h)| (n.as_str(), h))
        .collect();
    let c = &s.counters;
    pb::Status {
        api_version: scribe_api::API_VERSION,
        daemon_version: scribe_core::VERSION.to_owned(),
        run_state: s.state.name().to_owned(),
        hibernating_since_ms: since,
        hibernating_until_ms: until,
        hibernated_by: by,
        uptime_s: snap
            .now
            .duration_since(snap.started)
            .unwrap_or_default()
            .as_secs(),
        config_path: snap.config_path.clone(),
        config_loaded_ms: epoch_ms(snap.config_loaded),
        mode: scribe_api::mode_to_api(s.mode),
        profile: s.profile.clone(),
        learn_until_ms: s.learn_until.map(epoch_ms),
        sensor: Some(pb::Sensor {
            name: snap.sensor.name.clone(),
            process_info: snap.sensor.process_info,
            health: if !snap.sensor.capturing {
                "detached"
            } else if snap.sensor.fallback {
                "fallback"
            } else {
                "ok"
            }
            .into(),
            fallback: snap.sensor.fallback,
        }),
        storage: Some(pb::Storage {
            state: Some(pb::StorageTarget {
                name: "state".into(),
                kind: layout.state_kind.clone(),
                health: state_health.into(),
                detail: state_detail,
            }),
            sinks: layout
                .sink_kinds
                .iter()
                .map(|(name, kind)| {
                    let (health, detail) = sink_health
                        .get(name.as_str())
                        .map_or(("ok", String::new()), |h| health_name(h));
                    pb::StorageTarget {
                        name: name.clone(),
                        kind: kind.clone(),
                        health: health.into(),
                        detail,
                    }
                })
                .collect(),
        }),
        counters_since_ms: epoch_ms(c.since),
        counters: Some(pb::Counters {
            observations: c.observations,
            flows: c.flows,
            payloads: c.payloads,
            dns_responses: c.dns_responses,
            alerts: c.alerts,
            new_hosts: c.baseline_added,
            quic_unfinished: c.quic_unfinished,
            dropped_hibernating: c.dropped_hibernating,
            flows_per_s: snap.flows_per_s,
            events_per_s: snap.events_per_s,
            drops: total_drops(snap, view),
        }),
        critical: critical(snap, view, layout),
        modules: modules(snap),
        held_quic: s.held_quic as u64,
        dns_entries: s.dns_entries as u64,
    }
}

/// Every module built into this `scribed`; the enabled ones with their run state.
pub fn modules(snap: &Snapshot) -> Vec<pb::Module> {
    snap.modules_built
        .iter()
        .map(
            |id| match snap.status.modules.iter().find(|m| m.id == *id) {
                Some(m) => pb::Module {
                    id: m.id.to_owned(),
                    version: m.version,
                    enabled: true,
                    state: run_state_name(&m.state).into(),
                    health: match (&m.state, &m.health) {
                        (RunState::Failed(why), _) => why.clone(),
                        (_, scribe_module_api::ModuleHealth::Healthy) => "ok".into(),
                        (_, scribe_module_api::ModuleHealth::Degraded(why))
                        | (_, scribe_module_api::ModuleHealth::Unhealthy(why)) => why.clone(),
                    },
                    over_budget: m.over_budget,
                    drops: snap.module_drops.get(m.id).copied().unwrap_or(0),
                },
                None => pb::Module {
                    id: (*id).to_owned(),
                    enabled: false,
                    state: "stopped".into(),
                    health: "not enabled".into(),
                    ..Default::default()
                },
            },
        )
        .collect()
}

/// `Health`: unhealthy when the loop doesn't answer, the sensor isn't attached (and the daemon
/// isn't hibernating on purpose) or the state store is down; degraded with any critical metric.
pub fn health(snap: Option<&Snapshot>, view: &StorageView, layout: &Layout) -> pb::HealthReply {
    use pb::health_reply::Level;
    let Some(snap) = snap else {
        return pb::HealthReply {
            level: Level::Unhealthy as i32,
            reasons: vec!["the pipeline does not answer".into()],
        };
    };
    let items = critical(snap, view, layout);
    let unhealthy: Vec<String> = items
        .iter()
        .filter(|c| c.kind == "sensor_detached" || c.kind == "state_unhealthy")
        .map(|c| c.detail.clone())
        .collect();
    let (level, reasons) = if !unhealthy.is_empty() {
        (Level::Unhealthy, unhealthy)
    } else if !items.is_empty() {
        (
            Level::Degraded,
            items.into_iter().map(|c| c.detail).collect(),
        )
    } else {
        (Level::Healthy, Vec::new())
    };
    pb::HealthReply {
        level: level as i32,
        reasons,
    }
}

fn host_message(h: &Host, listed: &HashSet<String>, processes: &[String]) -> pb::Host {
    pb::Host {
        name: h.name.clone(),
        on_list: listed.contains(&h.name),
        first_seen_ms: epoch_ms(h.first_seen),
        last_seen_ms: epoch_ms(h.last_seen),
        conn_count: h.conn_count,
        req_count: h.req_count,
        bytes_out: h.bytes_out,
        tls_seen: h.tls_seen,
        plaintext_seen: h.plaintext_seen,
        processes: processes.to_vec(),
        unresolved: h.unresolved,
        // ECH is reported per flow; the host record doesn't keep it yet.
        ech: false,
    }
}

pub fn alert_message(a: &AlertRecord, acknowledged: bool) -> pb::Alert {
    pb::Alert {
        id: a.link.as_ref().map_or(0, |l| l.seq),
        ts_ms: epoch_ms(a.ts),
        host: a.host.clone(),
        dst: std::net::SocketAddr::new(a.dst_ip, a.dst_port).to_string(),
        process_path: a.process_path.clone(),
        score: a.score,
        reason: a.reason.clone(),
        acknowledged,
        notes: a
            .notes
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

fn entry_message(e: &scribe_storage_api::BaselineEntry) -> pb::BaselineEntry {
    pb::BaselineEntry {
        host: e.host.clone(),
        source: match e.source {
            EntrySource::Learned => "learned",
            EntrySource::Manual => "manual",
        }
        .into(),
        added_at_ms: epoch_ms(e.added_at),
    }
}

fn storage_error(what: &str, e: StorageError) -> RpcStatus {
    match e {
        StorageError::NotImplemented(_) | StorageError::Unsupported(_) => {
            RpcStatus::unimplemented(format!("{what}: {e}"))
        }
        e => RpcStatus::unavailable(format!("{what}: {e}")),
    }
}

/// Everything the service needs; cheap to clone.
#[derive(Clone)]
pub struct Api {
    pub commands: mpsc::Sender<Command>,
    pub storage: Arc<Storage>,
    pub alerts: broadcast::Sender<AlertRecord>,
    pub stopping: watch::Receiver<bool>,
    pub policy: AccessPolicy,
    pub layout: Layout,
}

type Reply<T> = Result<Response<T>, RpcStatus>;
type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, RpcStatus>> + Send>>;

impl Api {
    /// The main loop's snapshot; `unavailable` when it doesn't answer in time.
    pub async fn snapshot(&self) -> Result<Snapshot, RpcStatus> {
        self.ask(LOOP_TIMEOUT, |reply| Command::Describe { reply })
            .await
            .map(|snap| *snap)
    }

    /// Sends a command to the main loop and waits up to `limit` for its answer.
    async fn ask<R>(
        &self,
        limit: Duration,
        make: impl FnOnce(oneshot::Sender<R>) -> Command,
    ) -> Result<R, RpcStatus> {
        let (reply, answer) = oneshot::channel();
        let stuck = || RpcStatus::unavailable("the pipeline does not answer");
        let stopping = || RpcStatus::unavailable("scribed is stopping");
        tokio::time::timeout(limit, self.commands.send(make(reply)))
            .await
            .map_err(|_| stuck())?
            .map_err(|_| stopping())?;
        tokio::time::timeout(limit, answer)
            .await
            .map_err(|_| stuck())?
            .map_err(|_| stopping())
    }

    /// The caller of a control call, described for logs and audit events. A refusal is logged
    /// and stored as an `audit` event before it is returned.
    async fn control<T>(&self, request: &Request<T>, call: &str) -> Result<String, RpcStatus> {
        match self.policy.check(request, Access::Control) {
            Ok(caller) => {
                let who = caller.describe();
                info!(caller = %who, call, "control call");
                Ok(who)
            }
            Err(e) => {
                let who = scribe_api::access::caller(request)
                    .map_or_else(|_| "an unidentified caller".to_owned(), |c| c.describe());
                warn!(caller = %who, call, "control call refused: {}", e.message());
                let message = format!("refused {call} from {who}: {}", e.message());
                let _ = tokio::time::timeout(
                    LOOP_TIMEOUT,
                    self.commands.send(Command::Audit { message }),
                )
                .await;
                Err(e)
            }
        }
    }

    async fn status_now(&self) -> Result<pb::Status, RpcStatus> {
        let snap = self.snapshot().await?;
        let view = StorageView::read(&self.storage).await;
        Ok(status_message(&snap, &view, &self.layout))
    }

    /// The stored alert whose chain sequence is `id`.
    async fn find_alert(&self, id: u64) -> Result<AlertRecord, RpcStatus> {
        let mut offset = 0;
        loop {
            let query = EventQuery {
                kinds: vec![EventKind::Alert],
                offset,
                limit: Some(FIND_PAGE),
                ..Default::default()
            };
            let page = self
                .storage
                .query(&query)
                .await
                .map_err(|e| storage_error("alerts", e))?;
            let n = page.items.len();
            for event in page.items {
                if let StoredEvent::Alert(a) = event {
                    if a.link.as_ref().is_some_and(|l| l.seq == id) {
                        return Ok(a);
                    }
                }
            }
            if n < FIND_PAGE {
                return Err(RpcStatus::not_found(format!("no alert {id}")));
            }
            offset += n;
        }
    }

    async fn health_now(&self) -> pb::HealthReply {
        let snap = self.snapshot().await.ok();
        let view = StorageView::read(&self.storage).await;
        health(snap.as_ref(), &view, &self.layout)
    }

    async fn listed(&self, profile: &str) -> Result<HashSet<String>, RpcStatus> {
        match self.storage.state().baseline(profile).await {
            Ok(b) => Ok(b.entries.into_iter().map(|e| e.host).collect()),
            Err(StorageError::NotImplemented(_)) => Ok(HashSet::new()),
            Err(e) => Err(storage_error("baseline", e)),
        }
    }

    async fn processes(&self) -> HashMap<String, Vec<String>> {
        let mut by_host: HashMap<String, Vec<String>> = HashMap::new();
        if let Ok(rows) = self.storage.state().process_hosts(None).await {
            for row in rows {
                by_host.entry(row.host).or_default().push(row.process);
            }
        }
        by_host
    }

    /// Sends what `items` yields to a new stream, ending it when the daemon stops or the client
    /// goes away.
    fn stream<T: Send + 'static>(
        &self,
        produce: impl FnOnce(
                mpsc::Sender<Result<T, RpcStatus>>,
            ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + 'static,
    ) -> BoxStream<T> {
        let (tx, rx) = mpsc::channel(64);
        let mut stopping = self.stopping.clone();
        tokio::spawn(async move {
            if *stopping.borrow() {
                return;
            }
            let closed = tx.clone();
            tokio::select! {
                _ = produce(tx) => {}
                _ = stopping.changed() => {}
                _ = closed.closed() => {}
            }
        });
        Box::pin(ReceiverStream::new(rx))
    }
}

/// Alerts read per page while looking one up by id.
const FIND_PAGE: usize = 1000;
/// How long a control call waits for the main loop (a reload reads threat lists).
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
/// Hosts one `EditBaseline` call may name.
const MAX_EDIT: usize = 1000;
/// The longest host name (RFC 1035).
const MAX_HOST: usize = 253;

/// A host name or IP as typed, lower-cased; names with spaces, slashes or control characters
/// are refused.
fn host_name(raw: &str) -> Result<String, RpcStatus> {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let bad = host.is_empty()
        || host.len() > MAX_HOST
        || host.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '@' | '?' | '#')
        });
    if bad {
        Err(RpcStatus::invalid_argument(format!(
            "\"{raw}\" is not a host name or IP address"
        )))
    } else {
        Ok(host)
    }
}

fn record_to_alert(a: &AlertRecord) -> scribe_core::Alert {
    scribe_core::Alert {
        ts: a.ts,
        host: a.host.clone(),
        dst_ip: a.dst_ip,
        dst_port: a.dst_port,
        process_path: a.process_path.clone(),
        score: a.score,
        reason: a.reason.clone(),
        notes: a.notes.clone(),
    }
}

#[tonic::async_trait]
impl Scribe for Api {
    async fn get_status(&self, request: Request<pb::StatusRequest>) -> Reply<pb::Status> {
        self.policy.check(&request, Access::Read)?;
        let snap = self.snapshot().await?;
        let view = StorageView::read(&self.storage).await;
        Ok(Response::new(status_message(&snap, &view, &self.layout)))
    }

    async fn health(&self, request: Request<pb::HealthRequest>) -> Reply<pb::HealthReply> {
        self.policy.check(&request, Access::Read)?;
        Ok(Response::new(self.health_now().await))
    }

    async fn list_hosts(&self, request: Request<pb::ListHostsRequest>) -> Reply<pb::HostPage> {
        self.policy.check(&request, Access::Read)?;
        let r = request.into_inner();
        let profile = self.snapshot().await?.status.profile;
        let query = HostQuery {
            name_contains: (!r.name_contains.is_empty()).then_some(r.name_contains),
            offset: r.offset as usize,
            limit: (r.limit > 0).then_some(r.limit as usize),
        };
        let page = self
            .storage
            .state()
            .list_hosts(&query)
            .await
            .map_err(|e| storage_error("hosts", e))?;
        let listed = self.listed(&profile).await?;
        let processes = self.processes().await;
        Ok(Response::new(pb::HostPage {
            items: page
                .items
                .iter()
                .map(|h| {
                    host_message(
                        h,
                        &listed,
                        processes.get(&h.name).map_or(&[][..], Vec::as_slice),
                    )
                })
                .collect(),
            total: page.total,
        }))
    }

    async fn list_alerts(&self, request: Request<pb::ListAlertsRequest>) -> Reply<pb::AlertPage> {
        self.policy.check(&request, Access::Read)?;
        let r = request.into_inner();
        let query = EventQuery {
            since: r.since_ms.map(from_ms),
            until: None,
            kinds: vec![EventKind::Alert],
            offset: r.offset as usize,
            limit: (r.limit > 0).then_some(r.limit as usize),
        };
        let page = self
            .storage
            .query(&query)
            .await
            .map_err(|e| storage_error("alerts", e))?;
        let mut acked: HashMap<String, bool> = HashMap::new();
        let mut items = Vec::new();
        for event in &page.items {
            let StoredEvent::Alert(a) = event else {
                continue;
            };
            let key = scribe_policy::alert_key_for(
                a.host.as_deref(),
                a.dst_ip,
                a.process_path.as_deref(),
            );
            let ack = match acked.get(&key) {
                Some(v) => *v,
                None => {
                    let v = matches!(
                        self.storage.state().get_alert_state(&key).await,
                        Ok(Some(s)) if s.acknowledged
                    );
                    acked.insert(key, v);
                    v
                }
            };
            items.push(alert_message(a, ack));
        }
        Ok(Response::new(pb::AlertPage {
            items,
            total: page.total,
        }))
    }

    type WatchAlertsStream = BoxStream<pb::Alert>;

    async fn watch_alerts(
        &self,
        request: Request<pb::WatchAlertsRequest>,
    ) -> Reply<Self::WatchAlertsStream> {
        self.policy.check(&request, Access::Read)?;
        let mut alerts = self.alerts.subscribe();
        Ok(Response::new(self.stream(move |tx| {
            Box::pin(async move {
                loop {
                    match alerts.recv().await {
                        Ok(a) => {
                            if tx.send(Ok(alert_message(&a, false))).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("an alert watcher fell behind; {n} alerts skipped for it");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            })
        })))
    }

    async fn get_baseline(&self, request: Request<pb::GetBaselineRequest>) -> Reply<pb::Baseline> {
        self.policy.check(&request, Access::Read)?;
        let mut profile = request.into_inner().profile;
        if profile.is_empty() {
            profile = self.snapshot().await?.status.profile;
        }
        let baseline = match self.storage.state().baseline(&profile).await {
            Ok(b) => b,
            Err(StorageError::NotImplemented(_)) => scribe_storage_api::Baseline {
                profile: profile.clone(),
                entries: Vec::new(),
            },
            Err(e) => return Err(storage_error("baseline", e)),
        };
        Ok(Response::new(pb::Baseline {
            profile,
            entries: baseline.entries.iter().map(entry_message).collect(),
        }))
    }

    type ExportStream = BoxStream<pb::ExportItem>;

    async fn export(&self, request: Request<pb::ExportRequest>) -> Reply<Self::ExportStream> {
        self.policy.check(&request, Access::Read)?;
        let profile = self.snapshot().await?.status.profile;
        let listed = self.listed(&profile).await?;
        let processes = self.processes().await;
        let api = self.clone();
        Ok(Response::new(self.stream(move |tx| {
            Box::pin(async move {
                use pb::export_item::Item;
                let mut offset = 0;
                loop {
                    let query = HostQuery {
                        name_contains: None,
                        offset,
                        limit: Some(EXPORT_PAGE),
                    };
                    let page = match api.storage.state().list_hosts(&query).await {
                        Ok(p) => p,
                        Err(e) => {
                            let _ = tx.send(Err(storage_error("hosts", e))).await;
                            return;
                        }
                    };
                    let n = page.items.len();
                    for h in &page.items {
                        let item = host_message(
                            h,
                            &listed,
                            processes.get(&h.name).map_or(&[][..], Vec::as_slice),
                        );
                        let item = pb::ExportItem {
                            item: Some(Item::Host(item)),
                        };
                        if tx.send(Ok(item)).await.is_err() {
                            return;
                        }
                    }
                    if n < EXPORT_PAGE {
                        break;
                    }
                    offset += n;
                }
                match api.storage.state().baseline(&profile).await {
                    Ok(b) => {
                        for e in &b.entries {
                            let item = pb::ExportItem {
                                item: Some(Item::BaselineEntry(entry_message(e))),
                            };
                            if tx.send(Ok(item)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(StorageError::NotImplemented(_)) => {}
                    Err(e) => {
                        let _ = tx.send(Err(storage_error("baseline", e))).await;
                    }
                }
            })
        })))
    }

    async fn list_modules(
        &self,
        request: Request<pb::ListModulesRequest>,
    ) -> Reply<pb::ModuleList> {
        self.policy.check(&request, Access::Read)?;
        let snap = self.snapshot().await?;
        Ok(Response::new(pb::ModuleList {
            items: modules(&snap),
        }))
    }

    async fn get_module(&self, request: Request<pb::GetModuleRequest>) -> Reply<pb::Module> {
        self.policy.check(&request, Access::Read)?;
        let id = request.into_inner().id;
        let snap = self.snapshot().await?;
        modules(&snap)
            .into_iter()
            .find(|m| m.id == id)
            .map(Response::new)
            .ok_or_else(|| {
                RpcStatus::not_found(format!("module {id} is not built into this scribed"))
            })
    }

    async fn ack_alert(&self, request: Request<pb::AckAlertRequest>) -> Reply<pb::AckAlertReply> {
        let caller = self.control(&request, "AckAlert").await?;
        let id = request.into_inner().id;
        let record = self.find_alert(id).await?;
        let alert = record_to_alert(&record);
        let key = scribe_policy::alert_key(&alert);
        let state = match self.storage.state().get_alert_state(&key).await {
            Ok(s) => s,
            Err(StorageError::NotImplemented(_)) => None,
            Err(e) => return Err(storage_error("alert state", e)),
        };
        let changed = self
            .ask(CONTROL_TIMEOUT, |reply| Command::Acknowledge {
                id,
                alert,
                state,
                caller,
                reply,
            })
            .await?;
        Ok(Response::new(pb::AckAlertReply { changed }))
    }

    async fn set_mode(&self, request: Request<pb::SetModeRequest>) -> Reply<pb::SetModeReply> {
        let caller = self.control(&request, "SetMode").await?;
        let mode = scribe_api::mode_from_api(&request.get_ref().mode)
            .map_err(RpcStatus::invalid_argument)?;
        let previous = self
            .ask(CONTROL_TIMEOUT, |reply| Command::SetMode {
                mode,
                caller,
                reply,
            })
            .await?;
        Ok(Response::new(pb::SetModeReply {
            previous: scribe_api::mode_to_api(previous),
            mode: scribe_api::mode_to_api(mode),
        }))
    }

    async fn edit_baseline(
        &self,
        request: Request<pb::EditBaselineRequest>,
    ) -> Reply<pb::EditBaselineReply> {
        let caller = self.control(&request, "EditBaseline").await?;
        let r = request.into_inner();
        if r.add.len() + r.remove.len() > MAX_EDIT {
            return Err(RpcStatus::invalid_argument(format!(
                "at most {MAX_EDIT} hosts per call"
            )));
        }
        let add = r
            .add
            .iter()
            .map(|h| host_name(h))
            .collect::<Result<Vec<_>, _>>()?;
        let remove = r
            .remove
            .iter()
            .map(|h| host_name(h))
            .collect::<Result<Vec<_>, _>>()?;
        let edit = self
            .ask(CONTROL_TIMEOUT, |reply| Command::EditBaseline {
                add,
                remove,
                caller,
                reply,
            })
            .await?;
        Ok(Response::new(pb::EditBaselineReply {
            added: edit.added,
            removed: edit.removed,
            unchanged: edit.unchanged,
        }))
    }

    /// `config` goes first: when the file is rejected nothing else is reset.
    async fn reset(&self, request: Request<pb::ResetRequest>) -> Reply<pb::ResetReply> {
        let caller = self.control(&request, "Reset").await?;
        let r = request.into_inner();
        let all = !(r.counters || r.caches || r.config);
        let (counters, caches, config) = (all || r.counters, all || r.caches, all || r.config);
        let mut reply = pb::ResetReply::default();
        if config {
            let who = caller.clone();
            let report = self
                .ask(CONTROL_TIMEOUT, |reply| Command::Reload {
                    caller: who,
                    reply,
                })
                .await?
                .map_err(|e| {
                    RpcStatus::invalid_argument(format!(
                        "config not reloaded; the running config stays: {e}"
                    ))
                })?;
            reply.done.push("config".into());
            reply.applied = report.applied;
            reply.needs_restart = report.needs_restart;
        }
        if counters || caches {
            self.ask(CONTROL_TIMEOUT, |reply| Command::Reset {
                counters,
                caches,
                caller,
                reply,
            })
            .await?;
            if counters {
                reply.done.push("counters".into());
            }
            if caches {
                reply.done.push("caches".into());
            }
        }
        reply.status = Some(self.status_now().await?);
        Ok(Response::new(reply))
    }

    async fn hibernate(&self, request: Request<pb::HibernateRequest>) -> Reply<pb::Status> {
        let caller = self.control(&request, "Hibernate").await?;
        let for_ = request.into_inner().for_s.map(Duration::from_secs);
        if for_ == Some(Duration::ZERO) {
            return Err(RpcStatus::invalid_argument(
                "hibernate for zero seconds: leave out the duration for the maximum",
            ));
        }
        self.ask(CONTROL_TIMEOUT, |reply| Command::Hibernate {
            for_,
            caller,
            reply,
        })
        .await?;
        Ok(Response::new(self.status_now().await?))
    }

    async fn wakeup(&self, request: Request<pb::WakeupRequest>) -> Reply<pb::Status> {
        let caller = self.control(&request, "Wakeup").await?;
        self.ask(CONTROL_TIMEOUT, |reply| Command::Wakeup { caller, reply })
            .await?;
        Ok(Response::new(self.status_now().await?))
    }
}

/// The running API server.
pub struct ApiServer {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

/// How long shutdown waits for open calls before closing them.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

impl ApiServer {
    /// Serves `api` and `grpc.health.v1` on `listener`.
    #[cfg(unix)]
    pub fn spawn(listener: tokio::net::UnixListener, api: Api, stop: watch::Sender<bool>) -> Self {
        let (reporter, health_service) = tonic_health::server::health_reporter();
        let routes = tonic::service::Routes::new(scribe_api::unix::service(api.clone()))
            .add_service(health_service);
        let mut stopping = api.stopping.clone();
        let mut watcher = api.stopping.clone();
        let task = tokio::spawn(async move {
            let checker = tokio::spawn(async move {
                type Served = pb::scribe_server::ScribeServer<Api>;
                let mut every = tokio::time::interval(HEALTH_EVERY);
                loop {
                    tokio::select! {
                        _ = every.tick() => {}
                        _ = watcher.changed() => break,
                    }
                    let reply = api.health_now().await;
                    if reply.level == pb::health_reply::Level::Unhealthy as i32 {
                        reporter.set_not_serving::<Served>().await;
                        reporter
                            .set_service_status("", tonic_health::ServingStatus::NotServing)
                            .await;
                    } else {
                        reporter.set_serving::<Served>().await;
                        reporter
                            .set_service_status("", tonic_health::ServingStatus::Serving)
                            .await;
                    }
                }
            });
            let result = scribe_api::unix::serve(listener, routes, async move {
                let _ = stopping.wait_for(|s| *s).await;
            })
            .await;
            checker.abort();
            match result {
                Ok(()) => info!("local API stopped"),
                Err(e) => warn!("local API stopped with an error: {e}"),
            }
        });
        Self { stop, task }
    }

    /// Ends streams, then stops serving; calls still open after a grace period are cut.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let mut task = self.task;
        if tokio::time::timeout(SHUTDOWN_GRACE, &mut task)
            .await
            .is_err()
        {
            warn!("local API calls still open after {SHUTDOWN_GRACE:?}; closing them");
            task.abort();
            let _ = task.await;
        }
    }
}
