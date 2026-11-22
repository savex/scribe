//! Stored record layout shared by the SQL backends: one row per event with the kind, module,
//! host, schema version and a JSON payload, and epoch-millisecond timestamps.
//!
//! Payloads by kind (schema 2):
//! - `flow`: `pid`, `process_path`, `proto`, `src`, `dst_ip`, `dst_port`, `hostname`, `notes`,
//!   `security`, `bytes_out`, `kind` (`new_flow` | `payload` | `close`), `ech`. Schema 1 rows carry `url`
//!   instead of `notes` and may lack `src`; [`decode`] converts them.
//! - `alert`: `dst_ip`, `process_path`, `score`, `reason` (host in the row).
//! - `audit`: `message`.
//! - `metric`: `name`, `labels`, `value` (module in the row).
//! - module kinds (`<module>.<name>`): the module's own payload; the row's schema is the record's.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scribe_core::{FlowEvent, FlowKind, MetricSample, ModuleRecord, Notes, Protocol, Security};
use serde_json::{json, Value};

use crate::{AlertRecord, AuditRecord, ChainLink, StorageError, StoredEvent, SCHEMA_VERSION};

/// One stored event, as the backends keep it.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub ts: SystemTime,
    pub kind: String,
    pub module: Option<String>,
    pub host: Option<String>,
    pub schema: u32,
    pub payload: Value,
}

/// Milliseconds since the Unix epoch (negative before it).
pub fn to_millis(ts: SystemTime) -> i64 {
    match ts.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis().min(i64::MAX as u128) as i64,
        Err(e) => -(e.duration().as_millis().min(i64::MAX as u128) as i64),
    }
}

pub fn from_millis(ms: i64) -> SystemTime {
    if ms >= 0 {
        UNIX_EPOCH + Duration::from_millis(ms as u64)
    } else {
        UNIX_EPOCH - Duration::from_millis(ms.unsigned_abs())
    }
}

pub fn encode(event: &StoredEvent) -> Row {
    match event {
        StoredEvent::Flow(f) => Row {
            ts: f.ts,
            kind: "flow".into(),
            module: None,
            host: f.hostname.clone(),
            schema: SCHEMA_VERSION,
            payload: json!({
                "pid": f.pid,
                "process_path": f.process_path,
                "proto": protocol_name(f.proto),
                "src": f.src.to_string(),
                "dst_ip": f.dst_ip.to_string(),
                "dst_port": f.dst_port,
                "hostname": f.hostname,
                "ech": f.ech,
                "notes": f.notes,
                "security": security_name(f.security),
                "bytes_out": f.bytes_out,
                "kind": flow_kind_name(f.kind),
            }),
        },
        StoredEvent::Alert(a) => Row {
            ts: a.ts,
            kind: "alert".into(),
            module: None,
            host: a.host.clone(),
            schema: SCHEMA_VERSION,
            payload: with_link(
                json!({
                    "dst_ip": a.dst_ip.to_string(),
                    "dst_port": a.dst_port,
                    "process_path": a.process_path,
                    "score": a.score,
                    "reason": a.reason,
                    "notes": a.notes,
                }),
                a.link.as_ref(),
            ),
        },
        StoredEvent::Audit(a) => Row {
            ts: a.ts,
            kind: "audit".into(),
            module: None,
            host: None,
            schema: SCHEMA_VERSION,
            payload: with_link(json!({ "message": a.message }), a.link.as_ref()),
        },
        StoredEvent::Metric(m) => Row {
            ts: m.ts,
            kind: "metric".into(),
            module: Some(m.module.to_string()),
            host: None,
            schema: SCHEMA_VERSION,
            payload: json!({ "name": m.name, "labels": m.labels, "value": m.value }),
        },
        StoredEvent::Module(r) => Row {
            ts: r.ts,
            kind: r.kind.to_string(),
            module: Some(r.module.to_string()),
            host: r.host.clone(),
            schema: r.schema,
            payload: r.payload.clone(),
        },
    }
}

pub fn decode(row: Row) -> Result<StoredEvent, StorageError> {
    let bad = |what: &str| StorageError::Data(format!("{} record: {what}", row.kind));
    let p = &row.payload;
    let text = |key: &str| p.get(key).and_then(Value::as_str);
    let opt_text = |key: &str| text(key).map(str::to_owned);
    let ip = |key: &str| -> Result<IpAddr, StorageError> {
        text(key)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| bad(&format!("`{key}` is not an IP address")))
    };
    match row.kind.as_str() {
        "flow" => {
            let notes = match p.get("notes") {
                Some(v) if !v.is_null() => serde_json::from_value::<Notes>(v.clone())
                    .map_err(|e| bad(&format!("`notes`: {e}")))?,
                // Schema 1 kept the URL in its own field.
                _ => {
                    let mut notes = Notes::new();
                    if let Some(url) = text("url") {
                        notes.insert("url", json!(url));
                    }
                    notes
                }
            };
            let kind = match text("kind") {
                Some("new_flow") | None => FlowKind::NewFlow,
                Some("payload") | Some("request") => FlowKind::Payload,
                Some("close") => FlowKind::Close,
                Some("dns_response") => FlowKind::DnsResponse,
                Some(other) => return Err(bad(&format!("unknown flow kind `{other}`"))),
            };
            Ok(StoredEvent::Flow(FlowEvent {
                ts: row.ts,
                pid: p.get("pid").and_then(Value::as_u64).map(|n| n as u32),
                process_path: opt_text("process_path"),
                proto: match text("proto") {
                    Some("tcp") => Protocol::Tcp,
                    Some("udp") => Protocol::Udp,
                    Some("quic") => Protocol::Quic,
                    other => return Err(bad(&format!("unknown protocol {other:?}"))),
                },
                src: text("src")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
                dst_ip: ip("dst_ip")?,
                dst_port: p
                    .get("dst_port")
                    .and_then(Value::as_u64)
                    .and_then(|n| u16::try_from(n).ok())
                    .ok_or_else(|| bad("`dst_port` is not a port"))?,
                hostname: opt_text("hostname").or_else(|| row.host.clone()),
                ech: p.get("ech").and_then(Value::as_bool).unwrap_or(false),
                notes,
                security: match text("security") {
                    Some("tls") => Security::Tls,
                    Some("quic") => Security::Quic,
                    Some("plaintext") => Security::Plaintext,
                    Some("unknown") | None => Security::Unknown,
                    Some(other) => return Err(bad(&format!("unknown security `{other}`"))),
                },
                bytes_out: p.get("bytes_out").and_then(Value::as_u64).unwrap_or(0),
                kind,
            }))
        }
        "alert" => Ok(StoredEvent::Alert(AlertRecord {
            ts: row.ts,
            host: row.host.clone(),
            dst_ip: ip("dst_ip")?,
            dst_port: p
                .get("dst_port")
                .and_then(Value::as_u64)
                .and_then(|v| u16::try_from(v).ok())
                .unwrap_or(0),
            process_path: opt_text("process_path"),
            score: p.get("score").and_then(Value::as_u64).unwrap_or(0) as u32,
            reason: opt_text("reason").unwrap_or_default(),
            notes: p
                .get("notes")
                .cloned()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default(),
            link: read_link(p),
        })),
        "audit" => Ok(StoredEvent::Audit(AuditRecord {
            ts: row.ts,
            message: opt_text("message").unwrap_or_default(),
            link: read_link(p),
        })),
        "metric" => {
            let labels: BTreeMap<String, String> = match p.get("labels") {
                Some(Value::Object(map)) => map
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            v.as_str().map_or_else(|| v.to_string(), str::to_owned),
                        )
                    })
                    .collect(),
                _ => BTreeMap::new(),
            };
            Ok(StoredEvent::Metric(MetricSample {
                ts: row.ts,
                module: row.module.clone().ok_or_else(|| bad("no module"))?.into(),
                name: opt_text("name").ok_or_else(|| bad("no name"))?.into(),
                labels,
                value: p
                    .get("value")
                    .and_then(Value::as_f64)
                    .ok_or_else(|| bad("`value` is not a number"))?,
            }))
        }
        kind => {
            let module = row
                .module
                .clone()
                .filter(|m| kind.starts_with(&format!("{m}.")))
                .ok_or_else(|| bad("unknown kind or a module that doesn't match it"))?;
            Ok(StoredEvent::Module(ModuleRecord {
                ts: row.ts,
                module: module.into(),
                kind: kind.to_owned().into(),
                schema: row.schema,
                host: row.host.clone(),
                payload: row.payload.clone(),
            }))
        }
    }
}

fn protocol_name(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Quic => "quic",
    }
}

fn security_name(s: Security) -> &'static str {
    match s {
        Security::Tls => "tls",
        Security::Quic => "quic",
        Security::Plaintext => "plaintext",
        Security::Unknown => "unknown",
    }
}

/// Add `seq` and `prev_hmac` to an audit or alert payload.
fn with_link(mut payload: Value, link: Option<&ChainLink>) -> Value {
    if let (Some(link), Some(map)) = (link, payload.as_object_mut()) {
        map.insert("seq".into(), json!(link.seq));
        map.insert("prev_hmac".into(), json!(link.prev_hmac));
    }
    payload
}

fn read_link(p: &Value) -> Option<ChainLink> {
    Some(ChainLink {
        seq: p.get("seq")?.as_u64()?,
        prev_hmac: p.get("prev_hmac")?.as_str()?.to_owned(),
    })
}

/// The bytes a record's HMAC covers: its encoded row (kind, host, time, payload without the
/// chain fields) as compact JSON with sorted keys, so any backend computes the same value.
pub fn chain_bytes(event: &StoredEvent) -> Vec<u8> {
    let row = encode(event);
    let mut payload = row.payload;
    if let Some(map) = payload.as_object_mut() {
        map.remove("seq");
        map.remove("prev_hmac");
    }
    serde_json::to_vec(&json!({
        "kind": row.kind,
        "host": row.host,
        "ts_ms": to_millis(row.ts),
        "payload": payload,
    }))
    .expect("JSON values always serialize")
}

fn flow_kind_name(k: FlowKind) -> &'static str {
    match k {
        FlowKind::NewFlow => "new_flow",
        FlowKind::Payload => "payload",
        FlowKind::Close => "close",
        FlowKind::DnsResponse => "dns_response",
    }
}
