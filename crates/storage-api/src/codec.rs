//! Stored record layout shared by the SQL backends: one row per event with the kind, module,
//! host, schema version and a JSON payload, and epoch-millisecond timestamps.
//!
//! Payloads by kind (schema 2):
//! - `flow`: `pid`, `process_path`, `proto`, `src`, `dst_ip`, `dst_port`, `hostname`, `notes`,
//!   `security`, `bytes_out`, `kind` (`new_flow` | `payload` | `close`). Schema 1 rows carry `url`
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

use crate::{AlertRecord, AuditRecord, StorageError, StoredEvent, SCHEMA_VERSION};

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
            payload: json!({
                "dst_ip": a.dst_ip.to_string(),
                "process_path": a.process_path,
                "score": a.score,
                "reason": a.reason,
            }),
        },
        StoredEvent::Audit(a) => Row {
            ts: a.ts,
            kind: "audit".into(),
            module: None,
            host: None,
            schema: SCHEMA_VERSION,
            payload: json!({ "message": a.message }),
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
            process_path: opt_text("process_path"),
            score: p.get("score").and_then(Value::as_u64).unwrap_or(0) as u32,
            reason: opt_text("reason").unwrap_or_default(),
        })),
        "audit" => Ok(StoredEvent::Audit(AuditRecord {
            ts: row.ts,
            message: opt_text("message").unwrap_or_default(),
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

fn flow_kind_name(k: FlowKind) -> &'static str {
    match k {
        FlowKind::NewFlow => "new_flow",
        FlowKind::Payload => "payload",
        FlowKind::Close => "close",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> SystemTime {
        from_millis(1_700_000_000_123)
    }

    fn flow() -> FlowEvent {
        let mut notes = Notes::new();
        notes.insert("url", json!("http://plain.example.com/a"));
        FlowEvent {
            ts: ts(),
            pid: Some(100),
            process_path: Some("/usr/bin/curl".into()),
            proto: Protocol::Tcp,
            src: "10.0.0.2:50000".parse().unwrap(),
            dst_ip: "192.0.2.20".parse().unwrap(),
            dst_port: 80,
            hostname: Some("plain.example.com".into()),
            notes,
            security: Security::Plaintext,
            bytes_out: 96,
            kind: FlowKind::Payload,
        }
    }

    fn round_trip(event: StoredEvent) -> StoredEvent {
        decode(encode(&event)).unwrap()
    }

    #[test]
    fn millis_round_trip() {
        for ms in [0, 1, 1_700_000_000_123, -5_000] {
            assert_eq!(to_millis(from_millis(ms)), ms);
        }
    }

    #[test]
    fn every_kind_round_trips() {
        let StoredEvent::Flow(f) = round_trip(StoredEvent::Flow(flow())) else {
            panic!()
        };
        let want = flow();
        assert_eq!(
            (
                f.ts,
                f.pid,
                &f.process_path,
                f.proto,
                f.src,
                f.dst_ip,
                f.dst_port
            ),
            (
                want.ts,
                want.pid,
                &want.process_path,
                want.proto,
                want.src,
                want.dst_ip,
                want.dst_port
            )
        );
        assert_eq!(
            (&f.hostname, &f.notes, f.security, f.bytes_out, f.kind),
            (
                &want.hostname,
                &want.notes,
                want.security,
                want.bytes_out,
                want.kind
            )
        );

        let alert = AlertRecord {
            ts: ts(),
            host: None,
            dst_ip: "198.51.100.7".parse().unwrap(),
            process_path: Some("/opt/agent/bin/agent".into()),
            score: 80,
            reason: "raw_ip".into(),
        };
        let StoredEvent::Alert(a) = round_trip(StoredEvent::Alert(alert.clone())) else {
            panic!()
        };
        assert_eq!(
            (a.ts, a.host, a.dst_ip, a.process_path, a.score, a.reason),
            (
                alert.ts,
                alert.host,
                alert.dst_ip,
                alert.process_path,
                alert.score,
                alert.reason
            )
        );

        let StoredEvent::Audit(a) = round_trip(StoredEvent::Audit(AuditRecord {
            ts: ts(),
            message: "mode changed".into(),
        })) else {
            panic!()
        };
        assert_eq!(a.message, "mode changed");

        let metric = MetricSample {
            ts: ts(),
            module: "kperf".into(),
            name: "kperf.tcp_retrans".into(),
            labels: [("iface".to_owned(), "eth0".to_owned())].into(),
            value: 2.5,
        };
        let row = encode(&StoredEvent::Metric(metric.clone()));
        assert_eq!(row.module.as_deref(), Some("kperf"));
        let StoredEvent::Metric(m) = decode(row).unwrap() else {
            panic!()
        };
        assert_eq!(m, metric);

        let record = ModuleRecord {
            ts: ts(),
            module: "url".into(),
            kind: "url.request".into(),
            schema: 1,
            host: Some("plain.example.com".into()),
            payload: json!({ "url": "http://plain.example.com/" }),
        };
        let row = encode(&StoredEvent::Module(record.clone()));
        assert_eq!((row.schema, row.kind.as_str()), (1, "url.request"));
        let StoredEvent::Module(r) = decode(row).unwrap() else {
            panic!()
        };
        assert_eq!(r, record);
    }

    #[test]
    fn reads_schema_1_flows() {
        // As in testdata/db/seed_v1.sql.
        let row = Row {
            ts: ts(),
            kind: "flow".into(),
            module: None,
            host: Some("plain.example.com".into()),
            schema: 1,
            payload: json!({"pid":100,"process_path":"/usr/bin/curl","proto":"tcp","dst_ip":"192.0.2.20","dst_port":80,"hostname":"plain.example.com","url":"http://plain.example.com/x","security":"plaintext","bytes_out":512,"kind":"request"}),
        };
        let StoredEvent::Flow(f) = decode(row).unwrap() else {
            panic!()
        };
        assert_eq!(f.notes.get_str("url"), Some("http://plain.example.com/x"));
        assert_eq!(f.kind, FlowKind::Payload);
        assert_eq!(f.src.port(), 0, "schema 1 had no source address");
    }

    #[test]
    fn rejects_unreadable_rows() {
        let row = |kind: &str, module: Option<&str>, payload: Value| Row {
            ts: ts(),
            kind: kind.into(),
            module: module.map(str::to_owned),
            host: None,
            schema: 2,
            payload,
        };
        for (r, expected) in [
            (
                row("flow", None, json!({"proto":"sctp"})),
                "unknown protocol",
            ),
            (
                row("flow", None, json!({"proto":"tcp","dst_ip":"x"})),
                "`dst_ip` is not an IP",
            ),
            (
                row(
                    "flow",
                    None,
                    json!({"proto":"tcp","dst_ip":"192.0.2.1","dst_port":70000}),
                ),
                "`dst_port`",
            ),
            (
                row(
                    "flow",
                    None,
                    json!({"proto":"tcp","dst_ip":"192.0.2.1","dst_port":1,"kind":"x"}),
                ),
                "unknown flow kind",
            ),
            (row("metric", Some("k"), json!({"name":"k.x"})), "`value`"),
            (
                row("url.request", Some("kperf"), json!({})),
                "doesn't match",
            ),
            (row("dns", None, json!({})), "unknown kind"),
        ] {
            let err = decode(r).unwrap_err().to_string();
            assert!(err.contains(expected), "{err} vs {expected}");
        }
    }
}
