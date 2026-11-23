use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;
use std::time::SystemTime;

use scribe_core::{FlowEvent, MetricSample, ModuleRecord, Security};

/// Version of the stored record layout. Bump on incompatible changes.
/// 2: module records, metric samples and module state (specs 10.3).
pub const SCHEMA_VERSION: u32 = 4;

pub type HostId = i64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub id: HostId,
    pub name: String,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub conn_count: u64,
    pub req_count: u64,
    pub bytes_out: u64,
    pub tls_seen: bool,
    pub plaintext_seen: bool,
    /// The real name is unknown: the host is an IP, or only an ECH outer name was seen (FR-7).
    /// Only ever turns on.
    pub unresolved: bool,
}

/// Counter increments for one host. Backends must apply these as deltas
/// (e.g. `ON CONFLICT ... DO UPDATE SET n = n + excluded.n`), never read-modify-write.
#[derive(Debug, Clone)]
pub struct HostDelta {
    pub name: String,
    pub seen_at: SystemTime,
    pub connections: u64,
    pub requests: u64,
    pub bytes_out: u64,
    pub security: Security,
    /// The flow had no real name (no host name, or only an ECH outer name).
    pub unresolved: bool,
    /// The process that made the flow: the same deltas also count per process + host (FR-9).
    pub process: Option<String>,
}

/// Counters for one process + host pair (FR-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessHost {
    pub process: String,
    pub host: String,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub conn_count: u64,
    pub req_count: u64,
    pub bytes_out: u64,
}

/// One host's counters for one hour (FR-9; schema v4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHour {
    pub host: String,
    /// Start of the hour.
    pub hour: SystemTime,
    pub conn_count: u64,
    pub req_count: u64,
    pub bytes_out: u64,
}

/// The start of the hour `t` falls in.
pub fn hour_of(t: SystemTime) -> SystemTime {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs - secs % 3600)
}

#[derive(Debug, Clone, Default)]
pub struct HostQuery {
    pub name_contains: Option<String>,
    pub offset: usize,
    /// `None` returns all remaining rows.
    pub limit: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Total matching rows, if the backend can count cheaply.
    pub total: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntrySource {
    Learned,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineEntry {
    pub host: String,
    pub source: EntrySource,
    pub added_at: SystemTime,
}

/// The list of known hosts for one profile (e.g. "default", "work").
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    pub profile: String,
    pub entries: Vec<BaselineEntry>,
}

impl Baseline {
    pub fn contains(&self, host: &str) -> bool {
        self.entries.iter().any(|e| e.host == host)
    }
}

/// Dedupe / acknowledgement state for alerts, keyed by host + process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertState {
    pub key: String,
    pub last_alerted: SystemTime,
    pub acknowledged: bool,
}

#[derive(Debug, Clone)]
pub struct AlertRecord {
    pub ts: SystemTime,
    pub host: Option<String>,
    pub dst_ip: IpAddr,
    /// 0 in rows written before the port was stored.
    pub dst_port: u16,
    pub process_path: Option<String>,
    pub score: u32,
    pub reason: String,
    /// The flow's module notes (e.g. the URL); empty in older rows.
    pub notes: scribe_core::Notes,
    /// Place in the tamper-evident chain (NFR-18); `None` before the daemon sealed it.
    pub link: Option<ChainLink>,
}

/// One record's place in the audit / alert chain (NFR-18): a sequence number shared by audit and
/// alert records, and the HMAC of the record before it. Deleted or edited rows break the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLink {
    pub seq: u64,
    /// Lowercase hex HMAC-SHA256 of the previous record; empty for the first one.
    pub prev_hmac: String,
}

impl From<&scribe_core::Alert> for AlertRecord {
    fn from(a: &scribe_core::Alert) -> Self {
        Self {
            ts: a.ts,
            host: a.host.clone(),
            dst_ip: a.dst_ip,
            dst_port: a.dst_port,
            process_path: a.process_path.clone(),
            score: a.score,
            reason: a.reason.clone(),
            notes: a.notes.clone(),
            link: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub ts: SystemTime,
    pub message: String,
    /// Place in the tamper-evident chain (NFR-18); `None` before the daemon sealed it.
    pub link: Option<ChainLink>,
}

/// What a stored event is. Sinks subscribe by [`EventKind::name`]: `flow`, `alert`, `audit`,
/// `metric`, or a module record kind such as `url.request`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EventKind {
    Flow,
    Alert,
    Audit,
    /// Metric samples from any module.
    Metric,
    /// A module record kind, always `<module>.<name>`.
    Module(Cow<'static, str>),
}

impl EventKind {
    /// The core kinds, in the order the docs list them.
    pub const CORE: [EventKind; 4] = [
        EventKind::Flow,
        EventKind::Alert,
        EventKind::Audit,
        EventKind::Metric,
    ];

    pub fn name(&self) -> &str {
        match self {
            EventKind::Flow => "flow",
            EventKind::Alert => "alert",
            EventKind::Audit => "audit",
            EventKind::Metric => "metric",
            EventKind::Module(kind) => kind,
        }
    }

    /// The module that owns this kind, if any.
    pub fn module(&self) -> Option<&str> {
        match self {
            EventKind::Module(kind) => kind.split_once('.').map(|(m, _)| m),
            _ => None,
        }
    }

    /// Parse a name: a core kind, or `<module>.<name>` for a module record kind.
    pub fn parse(name: &str) -> Option<EventKind> {
        match name {
            "flow" => Some(EventKind::Flow),
            "alert" => Some(EventKind::Alert),
            "audit" => Some(EventKind::Audit),
            "metric" => Some(EventKind::Metric),
            _ => match name.split_once('.') {
                Some((module, rest)) if !module.is_empty() && !rest.is_empty() => {
                    Some(EventKind::Module(Cow::Owned(name.to_owned())))
                }
                _ => None,
            },
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone)]
pub enum StoredEvent {
    Flow(FlowEvent),
    Alert(AlertRecord),
    Audit(AuditRecord),
    Metric(MetricSample),
    Module(ModuleRecord),
}

impl StoredEvent {
    pub fn kind(&self) -> EventKind {
        match self {
            StoredEvent::Flow(_) => EventKind::Flow,
            StoredEvent::Alert(_) => EventKind::Alert,
            StoredEvent::Audit(_) => EventKind::Audit,
            StoredEvent::Metric(_) => EventKind::Metric,
            StoredEvent::Module(r) => EventKind::Module(r.kind.clone()),
        }
    }

    pub fn ts(&self) -> SystemTime {
        match self {
            StoredEvent::Flow(e) => e.ts,
            StoredEvent::Alert(e) => e.ts,
            StoredEvent::Audit(e) => e.ts,
            StoredEvent::Metric(e) => e.ts,
            StoredEvent::Module(e) => e.ts,
        }
    }

    /// The module that produced this event, if any.
    pub fn module(&self) -> Option<&str> {
        match self {
            StoredEvent::Metric(m) => Some(&m.module),
            StoredEvent::Module(r) => Some(&r.module),
            _ => None,
        }
    }
}

/// One module's stored state: key → JSON value.
pub type ModuleState = std::collections::BTreeMap<String, serde_json::Value>;

#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub since: Option<SystemTime>,
    pub until: Option<SystemTime>,
    pub kinds: Vec<EventKind>,
    pub offset: usize,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StoreCaps {
    pub transactions: bool,
    pub full_text_search: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SinkCaps {
    /// Supports [`crate::EventSink::query`].
    pub queryable: bool,
    /// Enforces retention itself; otherwise the manager does.
    pub native_retention: bool,
    pub max_batch: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    Ok,
    Degraded(String),
    Down(String),
}
