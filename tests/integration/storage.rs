//! Storage manager → SQLite (direct and running), and released snapshots → migration → codec →
//! readers.

use scribe_storage_api::{
    EventKind, EventQuery, EventSink, Health, HostDelta, StateStore, StoredEvent, SCHEMA_VERSION,
};
use scribe_storage_conformance::block_on;
use scribe_storage_manager::{Registry, RunOptions, SpoolOptions, StorageConfig, StorageManager};
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

#[tokio::test(flavor = "multi_thread")]
async fn the_running_storage_writes_through_to_sqlite() {
    // Writer tasks, spool, outage buffer and cache in front of real SQLite files.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scribe.db");
    let config = StorageConfig::sqlite_default(path.to_str().unwrap());
    let manager = StorageManager::from_config(&Registry::with_builtin(), &config).unwrap();
    manager.migrate().await.unwrap();
    let storage = manager.start(RunOptions {
        spool: Some(SpoolOptions::new(dir.path().join("spool"), 1 << 20, 0)),
        ..RunOptions::default()
    });

    // A current timestamp: the default sink keeps 30 days, and retention runs at start.
    let flow = flow("192.0.2.10:443")
        .host("api.example.com")
        .tls()
        .at(std::time::SystemTime::now())
        .build();
    storage.publish(&[StoredEvent::Flow(flow.clone())]);
    storage
        .state()
        .upsert_host(&HostDelta {
            name: "api.example.com".into(),
            seen_at: flow.ts,
            connections: 1,
            requests: 0,
            bytes_out: 512,
            security: flow.security,
            unresolved: false,
            process: None,
        })
        .await
        .unwrap();
    storage.flush().await;

    let host = storage
        .state()
        .get_host("api.example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((host.conn_count, host.bytes_out), (1, 512));
    let health = storage.health().await;
    assert_eq!(health.overall, Health::Ok, "{health:?}");
    let status = storage.sink_status()[0].clone();
    assert_eq!((status.written, status.spool_events), (1, 0));
    storage.shutdown().await;

    // Everything is in the file: read it back with a fresh sink.
    let sink = sqlite_sink("check", &path);
    let page = sink.query(&EventQuery::default()).await.unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].kind(), EventKind::Flow);
}
