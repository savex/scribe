//! Config → resolve → storage manager → backends, through `scribed`'s `serve`.

use scribe_core::platform::DefaultPaths;
use scribe_daemon::app::serve;
use scribe_daemon::config::{context, parse, resolve, HostFacts, Settings, Source};

fn settings_in(dir: &std::path::Path) -> Settings {
    let text = format!("data_dir = '{}'\n[log]\nfile = ''\n", dir.display());
    let source = Source::File("test.toml".into());
    let config = parse(&text, &source, &context()).unwrap();
    resolve(
        config,
        source,
        &DefaultPaths::current().unwrap(),
        &HostFacts,
    )
    .unwrap()
}

#[test]
fn serve_creates_folders_and_stops_on_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(serve(settings_in(&data), std::future::ready(())))
        .unwrap();
    assert!(data.is_dir());
    assert!(data.join("spool").is_dir());
    assert!(
        data.join("state.db").is_file(),
        "storage opened and migrated"
    );
}

/// INT-10: sensor → enrichment → modules → policy → storage, through `serve_with` on SQLite.
#[test]
fn pipeline_stores_flows_counters_and_alerts() {
    use scribe_core::{FlowKind, Security};
    use scribe_daemon::app::serve_with;
    use scribe_storage_api::{EventQuery, EventSink, StateStore, StoredEvent};
    use scribe_test_support::packets::tls::client_hello_sni;
    use scribe_test_support::{flow, FakeSensor};

    let dir = tempfile::tempdir().unwrap();
    let text = format!(
        "mode = 'caution'\ndata_dir = '{}'\n[log]\nfile = ''\n",
        dir.path().display()
    );
    let source = Source::File("test.toml".into());
    let settings = resolve(
        parse(&text, &source, &context()).unwrap(),
        source,
        &DefaultPaths::current().unwrap(),
        &HostFacts,
    )
    .unwrap();
    let mut tls = flow("192.0.2.10:443")
        .process(100, "/usr/bin/curl")
        .bytes(512)
        .payload(&client_hello_sni("api.example.com"))
        .observe();
    tls.event.kind = FlowKind::NewFlow;
    tls.event.security = Security::Unknown;
    let mut raw = flow("198.51.100.7:8443")
        .process(200, "/opt/agent/bin/agent")
        .payload(b"\x00\x01bin")
        .observe();
    raw.event.kind = FlowKind::NewFlow;
    let sensor = FakeSensor::from_observations(vec![tls, raw]);

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(serve_with(
        settings,
        Box::new(sensor),
        std::future::ready(()),
    ))
    .unwrap();

    let state = scribe_tests::sqlite_store(&dir.path().join("state.db"));
    let api = rt
        .block_on(state.get_host("api.example.com"))
        .unwrap()
        .expect("named host stored");
    assert_eq!(
        (api.conn_count, api.bytes_out, api.tls_seen),
        (1, 512, true)
    );
    let raw_host = rt
        .block_on(state.get_host("198.51.100.7"))
        .unwrap()
        .expect("IP host stored");
    assert!(raw_host.unresolved);
    let curl = rt
        .block_on(state.process_hosts(Some("/usr/bin/curl")))
        .unwrap();
    assert_eq!(curl.len(), 1);
    assert!(rt
        .block_on(state.get_alert_state("198.51.100.7|/opt/agent/bin/agent"))
        .unwrap()
        .is_some());

    let sink = scribe_tests::sqlite_sink("local-history", &dir.path().join("events.db"));
    let events = rt
        .block_on(sink.query(&EventQuery::default()))
        .unwrap()
        .items;
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, StoredEvent::Flow(_)))
            .count(),
        2
    );
    let alerts: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            StoredEvent::Alert(a) => Some(a),
            _ => None,
        })
        .collect();
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        (alerts[0].reason.as_str(), alerts[0].dst_port),
        ("raw_ip", 8443)
    );
}
