use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;
use std::time::SystemTime;

use scribe_core::{FlowEvent, MetricSample, ModuleRecord, Security};

/// Version of the stored record layout. Bump on incompatible changes.
/// 2: module records, metric samples and module state (specs 10.3).
pub const SCHEMA_VERSION: u32 = 2;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::UNIX_EPOCH;

    mod functional {
        use super::*;

        #[test]
        fn kinds_round_trip_through_their_names() {
            for kind in EventKind::CORE {
                assert_eq!(EventKind::parse(kind.name()), Some(kind.clone()));
                assert_eq!(kind.module(), None);
            }
            let module = EventKind::parse("url.request").unwrap();
            assert_eq!(module, EventKind::Module(Cow::Borrowed("url.request")));
            assert_eq!(module.name(), "url.request");
            assert_eq!(module.module(), Some("url"));
            assert_eq!(module.to_string(), "url.request");
            for bad in ["", "flows", "url", ".request", "url.", "Flow"] {
                assert_eq!(EventKind::parse(bad), None, "{bad:?}");
            }
        }

        #[test]
        fn module_events_report_their_kind_and_module() {
            let record = StoredEvent::Module(ModuleRecord {
                ts: UNIX_EPOCH,
                module: "url".into(),
                kind: "url.request".into(),
                schema: 1,
                host: Some("plain.example.com".into()),
                payload: serde_json::json!({ "url": "http://plain.example.com/" }),
            });
            assert_eq!(record.kind().name(), "url.request");
            assert_eq!(record.module(), Some("url"));
            assert_eq!(record.ts(), UNIX_EPOCH);

            let metric = StoredEvent::Metric(MetricSample {
                ts: UNIX_EPOCH,
                module: "kperf".into(),
                name: "kperf.tcp_retrans".into(),
                labels: BTreeMap::new(),
                value: 3.0,
            });
            assert_eq!(metric.kind(), EventKind::Metric);
            assert_eq!(metric.module(), Some("kperf"));

            let audit = StoredEvent::Audit(AuditRecord {
                ts: UNIX_EPOCH,
                message: "x".into(),
            });
            assert_eq!(audit.module(), None);
        }
    }
}
