use std::net::IpAddr;
use std::time::SystemTime;

use scribe_core::{FlowEvent, Security};

/// Version of the stored record layout. Bump on incompatible changes.
pub const SCHEMA_VERSION: u32 = 1;

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
    pub process_path: Option<String>,
    pub score: u32,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub ts: SystemTime,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Flow,
    Alert,
    Audit,
}

#[derive(Debug, Clone)]
pub enum StoredEvent {
    Flow(FlowEvent),
    Alert(AlertRecord),
    Audit(AuditRecord),
}

impl StoredEvent {
    pub fn kind(&self) -> EventKind {
        match self {
            StoredEvent::Flow(_) => EventKind::Flow,
            StoredEvent::Alert(_) => EventKind::Alert,
            StoredEvent::Audit(_) => EventKind::Audit,
        }
    }

    pub fn ts(&self) -> SystemTime {
        match self {
            StoredEvent::Flow(e) => e.ts,
            StoredEvent::Alert(e) => e.ts,
            StoredEvent::Audit(e) => e.ts,
        }
    }
}

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
