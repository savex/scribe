//! Storage manager → SQLite, and released snapshots → migration → codec → readers.

use scribe_storage_api::{
    EventKind, EventQuery, EventSink, StateStore, StoredEvent, SCHEMA_VERSION,
};
use scribe_storage_conformance::block_on;
use scribe_storage_manager::{Registry, StorageConfig, StorageManager};
use scribe_test_support::flow;
use scribe_tests::{sqlite_sink, sqlite_snapshot, sqlite_store};

#[test]
fn manager_publishes_through_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scribe.db");
    let config = StorageConfig::sqlite_default(path.to_str().unwrap());
    let manager = StorageManager::from_config(&Registry::with_builtin(), &config).unwrap();
    block_on(manager.migrate()).unwrap();
    let event = StoredEvent::Flow(flow("192.0.2.10:443").host("api.example.com").tls().build());
    block_on(manager.publish(&[event])).unwrap();
    let sink = manager.sinks().next().unwrap();
    let page = block_on(sink.query(&EventQuery::default())).unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].kind(), EventKind::Flow);
}

#[test]
fn released_snapshots_migrate_to_the_latest_schema() {
    for version in 1..=SCHEMA_VERSION {
        let dir = tempfile::tempdir().unwrap();
        let s = sqlite_store(&sqlite_snapshot(version, dir.path()));
        assert_eq!(s.schema_version().unwrap(), version);
        block_on(s.migrate()).unwrap_or_else(|e| panic!("v{version}: {e}"));
        assert_eq!(
            s.schema_version().unwrap(),
            SCHEMA_VERSION,
            "from v{version}"
        );
        let host = block_on(s.get_host("api.example.com")).unwrap();
        assert!(
            host.is_some(),
            "v{version}: seeded host readable after migration"
        );
    }
}

#[test]
fn reads_rows_written_by_schema_1() {
    let dir = tempfile::tempdir().unwrap();
    let s = sqlite_sink("old", &sqlite_snapshot(1, dir.path()));
    block_on(s.migrate()).unwrap();
    let all = block_on(s.query(&EventQuery::default())).unwrap();
    assert_eq!(all.total, Some(4));
    let kinds: Vec<String> = all.items.iter().map(|e| e.kind().to_string()).collect();
    assert_eq!(kinds, ["flow", "flow", "alert", "audit"]);
    let StoredEvent::Alert(alert) = &all.items[2] else {
        panic!()
    };
    assert_eq!(alert.reason, "raw_ip");
    assert_eq!(alert.score, 80);
}

#[test]
fn reads_the_v2_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let s = sqlite_sink("v2", &sqlite_snapshot(2, dir.path()));
    block_on(s.migrate()).unwrap();
    let all = block_on(s.query(&EventQuery::default())).unwrap();
    assert_eq!(
        all.total,
        Some(7),
        "4 v1 events, a v2 flow, a url.request, a metric"
    );
    let flow = all
        .items
        .iter()
        .find_map(|e| match e {
            StoredEvent::Flow(f) if f.notes.get_str("url").is_some() => Some(f),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        flow.notes.get_str("url"),
        Some("http://plain.example.com/download?id=<redacted>")
    );
    assert_eq!(
        flow.src.port(),
        50005,
        "the v2 row carries its source address"
    );
    assert!(all
        .items
        .iter()
        .any(|e| matches!(e, StoredEvent::Module(r) if r.kind == "url.request")));
    assert!(all
        .items
        .iter()
        .any(|e| matches!(e, StoredEvent::Metric(m) if m.name == "url.requests")));
}
