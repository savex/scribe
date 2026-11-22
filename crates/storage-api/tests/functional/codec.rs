//! Functional tests for `scribe_storage_api::codec` (moved from `src/codec.rs`).

use scribe_core::{FlowEvent, FlowKind, MetricSample, ModuleRecord, Notes, Protocol, Security};
use scribe_storage_api::codec::*;
use scribe_storage_api::{AlertRecord, AuditRecord, StoredEvent};
use serde_json::{json, Value};
use std::time::SystemTime;

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
        ech: true,
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
    assert!(f.ech, "ech round-trips");

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
