//! SQLite-specific event sink behaviour beyond the conformance suite.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scribe_core::{MetricSample, ModuleRecord};
use scribe_storage_api::{AuditRecord, EventKind, EventQuery, EventSink, StoredEvent};
use scribe_storage_conformance::block_on;
use scribe_storage_sqlite::SqliteSink;
use scribe_test_support::flow;
use serde_json::json;

fn sink(dir: &Path) -> SqliteSink {
    let path = dir.join("events.db").to_string_lossy().into_owned();
    let s = SqliteSink::from_options("local", &HashMap::from([("path".to_owned(), path)])).unwrap();
    block_on(s.migrate()).unwrap();
    s
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000 + secs)
}

fn audit(secs: u64, message: &str) -> StoredEvent {
    StoredEvent::Audit(AuditRecord {
        ts: at(secs),
        message: message.into(),
        link: None,
    })
}

fn metric(secs: u64) -> StoredEvent {
    StoredEvent::Metric(MetricSample {
        ts: at(secs),
        module: "kperf".into(),
        name: "kperf.tcp_retrans".into(),
        labels: Default::default(),
        value: secs as f64,
    })
}

fn names(items: &[StoredEvent]) -> Vec<String> {
    items
        .iter()
        .map(|e| match e {
            StoredEvent::Audit(a) => a.message.clone(),
            StoredEvent::Metric(m) => format!("metric@{}", m.value),
            other => other.kind().to_string(),
        })
        .collect()
}

#[test]
fn queries_merge_events_and_metrics_by_time() {
    let dir = tempfile::tempdir().unwrap();
    let s = sink(dir.path());
    block_on(s.write_batch(&[audit(3, "c"), metric(2), audit(1, "a"), metric(3)])).unwrap();
    block_on(
        s.write_batch(&[StoredEvent::Flow(
            flow("192.0.2.10:443")
                .host("api.example.com")
                .tls()
                .at(at(4))
                .build(),
        )]),
    )
    .unwrap();

    let all = block_on(s.query(&EventQuery::default())).unwrap();
    assert_eq!(all.total, Some(5));
    assert_eq!(
        names(&all.items),
        ["a", "metric@2", "c", "metric@3", "flow"]
    );

    let window = block_on(s.query(&EventQuery {
        since: Some(at(2)),
        until: Some(at(4)),
        ..Default::default()
    }))
    .unwrap();
    assert_eq!(
        names(&window.items),
        ["metric@2", "c", "metric@3"],
        "since inclusive, until exclusive"
    );

    let page = block_on(s.query(&EventQuery {
        offset: 1,
        limit: Some(2),
        ..Default::default()
    }))
    .unwrap();
    assert_eq!(names(&page.items), ["metric@2", "c"]);
    assert_eq!(page.total, Some(5), "total ignores paging");

    let audits = block_on(s.query(&EventQuery {
        kinds: vec![EventKind::Audit, EventKind::Metric],
        since: Some(at(3)),
        ..Default::default()
    }))
    .unwrap();
    assert_eq!(names(&audits.items), ["c", "metric@3"]);

    let none = block_on(s.query(&EventQuery {
        kinds: vec![EventKind::parse("url.request").unwrap()],
        ..Default::default()
    }))
    .unwrap();
    assert!(none.items.is_empty());
    assert_eq!(none.total, Some(0));
}

#[test]
fn a_bad_record_rolls_back_the_whole_batch() {
    let dir = tempfile::tempdir().unwrap();
    let s = sink(dir.path());
    let mismatched = StoredEvent::Module(ModuleRecord {
        ts: at(1),
        module: "url".into(),
        kind: "kperf.sample".into(), // kind must start with the module id
        schema: 1,
        host: None,
        payload: json!({}),
    });
    assert!(block_on(s.write_batch(&[audit(1, "kept?"), mismatched])).is_err());
    let all = block_on(s.query(&EventQuery::default())).unwrap();
    assert!(
        all.items.is_empty(),
        "nothing from the failed batch is stored"
    );
}
