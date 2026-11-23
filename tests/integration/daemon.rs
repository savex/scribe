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

/// Commands reach the running daemon: hibernate (capped, audited, alerted), status, reset, wakeup.
#[test]
fn commands_drive_the_run_states() {
    use scribe_daemon::app::{serve_controlled, Command};
    use scribe_storage_api::{EventQuery, EventSink, StoredEvent};
    use scribe_test_support::FakeSensor;
    use std::time::Duration;
    use tokio::sync::{mpsc, oneshot};

    let dir = tempfile::tempdir().unwrap();
    let settings = settings_in(dir.path());
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (tx, rx) = mpsc::channel(4);
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let daemon = serve_controlled(
            settings,
            Box::new(FakeSensor::new(vec![])),
            Some(rx),
            async {
                let _ = stop_rx.await;
            },
        );
        let driver = async move {
            let ask = |make: Box<dyn FnOnce(oneshot::Sender<_>) -> Command + Send>| {
                let tx = tx.clone();
                async move {
                    let (reply, answer) = oneshot::channel();
                    tx.send(make(reply)).await.unwrap();
                    answer.await.unwrap()
                }
            };
            let s = ask(Box::new(|reply| Command::Hibernate {
                for_: Some(Duration::from_secs(10 * 3600)),
                caller: "test".into(),
                reply,
            }))
            .await;
            assert_eq!(s.state.name(), "hibernating");
            let s = ask(Box::new(|reply| Command::Reset {
                counters: true,
                caches: true,
                reply,
            }))
            .await;
            assert_eq!(s.counters.flows, 0);
            let s = ask(Box::new(|reply| Command::Wakeup {
                caller: "test".into(),
                reply,
            }))
            .await;
            assert_eq!(s.state.name(), "running");
            let s = ask(Box::new(|reply| Command::Status { reply })).await;
            assert_eq!(s.state.name(), "running");
            stop_tx.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(daemon, driver);
        result.unwrap();
    });

    let sink = scribe_tests::sqlite_sink("local-history", &dir.path().join("events.db"));
    let events = rt
        .block_on(sink.query(&EventQuery::default()))
        .unwrap()
        .items;
    let audits: Vec<String> = events
        .iter()
        .filter_map(|e| match e {
            StoredEvent::Audit(a) => Some(a.message.clone()),
            _ => None,
        })
        .collect();
    assert!(audits[0].starts_with("scribed "), "{audits:?}");
    assert!(
        audits[1].starts_with("hibernate by test until "),
        "{audits:?}"
    );
    assert_eq!(audits[2], "wakeup by test");
    assert_eq!(audits.last().map(String::as_str), Some("scribed stopped"));
    assert!(events
        .iter()
        .any(|e| matches!(e, StoredEvent::Alert(a) if a.reason == "hibernated")));
}

/// INT-07: a config reload reaches the policy and the modules; restart-only keys are reported;
/// a broken file is refused and the running config stays.
#[test]
fn config_reload_applies_live_keys_and_refuses_broken_files() {
    use scribe_core::Mode;
    use scribe_daemon::app::{serve_controlled, Command};
    use scribe_daemon::config::load_settings;
    use scribe_test_support::FakeSensor;
    use tokio::sync::{mpsc, oneshot};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scribe.toml");
    let base = format!("data_dir = '{}'\n[log]\nfile = ''\n", dir.path().display());
    std::fs::write(&path, format!("mode = 'learn'\n{base}")).unwrap();
    let settings = load_settings(Some(&path), None).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (tx, rx) = mpsc::channel(4);
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let daemon = serve_controlled(
            settings,
            Box::new(FakeSensor::new(vec![])),
            Some(rx),
            async {
                let _ = stop_rx.await;
            },
        );
        let driver = async move {
            let reload = || async {
                let (reply, answer) = oneshot::channel();
                tx.send(Command::Reload { caller: "test".into(), reply }).await.unwrap();
                answer.await.unwrap()
            };
            let status = || async {
                let (reply, answer) = oneshot::channel();
                tx.send(Command::Status { reply }).await.unwrap();
                answer.await.unwrap()
            };

            std::fs::write(
                &path,
                format!("mode = 'alert'\n{base}rotate = 'size'\n[policy]\nthreshold = 40\n[modules.url]\nquery = 'strip'\n"),
            )
            .unwrap();
            let report = reload().await.unwrap();
            assert_eq!(report.applied, ["mode", "policy", "modules"]);
            assert_eq!(report.needs_restart, ["log (file, output, format, rotation)"]);
            assert_eq!(status().await.mode, Mode::Alert);

            std::fs::write(&path, format!("mode = 'paranoid'\n{base}")).unwrap();
            let err = reload().await.unwrap_err();
            assert!(err.contains("unknown variant `paranoid`"), "{err}");
            assert_eq!(status().await.mode, Mode::Alert, "the running config stays");

            std::fs::write(
                &path,
                format!("mode = 'alert'\n{base}rotate = 'size'\n[policy]\nthreshold = 40\n[modules.url]\nquery = 'strip'\n"),
            )
            .unwrap();
            let again = reload().await.unwrap();
            assert!(again.applied.is_empty(), "nothing new to apply");
            assert_eq!(again.needs_restart, ["log (file, output, format, rotation)"], "still pending");
            stop_tx.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(daemon, driver);
        result.unwrap();
    });
}

/// A run that didn't remove its marker is reported at the next start; the audit chain of both
/// runs verifies with the install's key.
#[test]
fn an_unclean_stop_is_audited_and_the_chain_verifies() {
    use scribe_daemon::app::{serve, RUNNING_MARKER};
    use scribe_daemon::chain::{verify, Chain};
    use scribe_storage_api::{EventQuery, EventSink, StoredEvent};

    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(serve(settings_in(dir.path()), std::future::ready(())))
        .unwrap();
    assert!(
        !dir.path().join(RUNNING_MARKER).exists(),
        "removed at a clean stop"
    );
    std::fs::write(
        dir.path().join(RUNNING_MARKER),
        "pid 1 started 2026-11-22T10:00:00Z\n",
    )
    .unwrap();
    rt.block_on(serve(settings_in(dir.path()), std::future::ready(())))
        .unwrap();

    let sink = scribe_tests::sqlite_sink("local-history", &dir.path().join("events.db"));
    let events = rt
        .block_on(sink.query(&EventQuery::default()))
        .unwrap()
        .items;
    let audits: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            StoredEvent::Audit(a) => Some(a.message.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(audits.len(), 5, "{audits:?}");
    assert!(
        audits[2].starts_with("previous run did not stop cleanly (crash or kill): pid 1"),
        "{audits:?}"
    );
    let chain = Chain::open(dir.path()).unwrap();
    assert_eq!(chain.seq(), 5);
    assert!(verify(chain.key(), &events).is_empty());
}

// ─── Restarts and profiles (INT-05, INT-06, SCN-20, SCN-25) ─────────────────

fn settings_with(dir: &std::path::Path, extra: &str) -> Settings {
    let text = format!(
        "data_dir = '{}'\n{extra}\n[log]\nfile = ''\n",
        dir.display()
    );
    let source = Source::File("test.toml".into());
    resolve(
        parse(&text, &source, &context()).unwrap(),
        source,
        &DefaultPaths::current().unwrap(),
        &HostFacts,
    )
    .unwrap()
}

/// One daemon run over `observations`, stopped as soon as they are processed.
fn run_once(dir: &std::path::Path, extra: &str, observations: Vec<scribe_core::Observation>) {
    let sensor = scribe_test_support::FakeSensor::from_observations(observations);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(scribe_daemon::app::serve_with(
        settings_with(dir, extra),
        Box::new(sensor),
        std::future::ready(()),
    ))
    .unwrap();
}

// Observations carry the current time: the sink's 30-day retention runs at each start and would
// delete rows from the builders' fixed 2023 timestamp.
fn tls(dst: &str, sni: &str) -> scribe_core::Observation {
    let mut o = scribe_test_support::flow(dst)
        .at(std::time::SystemTime::now())
        .payload(&scribe_test_support::packets::tls::client_hello_sni(sni))
        .bytes(100)
        .observe();
    o.event.kind = scribe_core::FlowKind::NewFlow;
    o.event.security = scribe_core::Security::Unknown;
    o
}

fn request(url: &str) -> scribe_core::Observation {
    scribe_test_support::flow("192.0.2.20:80")
        .at(std::time::SystemTime::now())
        .http_get(url)
        .observe()
}

fn stored(dir: &std::path::Path) -> Vec<scribe_storage_api::StoredEvent> {
    use scribe_storage_api::{EventQuery, EventSink};
    let sink = scribe_tests::sqlite_sink("local-history", &dir.join("events.db"));
    futures_block(sink.query(&EventQuery::default()))
        .unwrap()
        .items
}

fn futures_block<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn alerts_for(events: &[scribe_storage_api::StoredEvent], host: &str) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, scribe_storage_api::StoredEvent::Alert(a) if a.host.as_deref() == Some(host)))
        .count()
}

/// INT-05 and INT-06: the URL module's records reach the event sink, and its state is handed back
/// at the next start, so its counter continues.
#[test]
fn module_output_is_stored_and_its_state_survives_a_restart() {
    use scribe_storage_api::{StateStore, StoredEvent};
    let dir = tempfile::tempdir().unwrap();
    run_once(
        dir.path(),
        "",
        vec![request("http://plain.example.com/a?x=1")],
    );
    run_once(dir.path(), "", vec![request("http://plain.example.com/b")]);

    let events = stored(dir.path());
    let urls: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            StoredEvent::Module(r) if r.kind == "url.request" => r.payload["url"].as_str(),
            _ => None,
        })
        .collect();
    assert_eq!(
        urls,
        [
            "http://plain.example.com/a?x=<redacted>",
            "http://plain.example.com/b"
        ]
    );
    let state = scribe_tests::sqlite_store(&dir.path().join("state.db"));
    let module = futures_block(state.module_state("url")).unwrap();
    assert_eq!(
        module["requests.plain.example.com"],
        serde_json::json!(2),
        "counter continued"
    );
}

/// SCN-20: hosts, counters and the learned baseline survive a restart on the same files.
#[test]
fn restart_keeps_hosts_counters_and_baseline() {
    use scribe_storage_api::StateStore;
    let dir = tempfile::tempdir().unwrap();
    run_once(
        dir.path(),
        "mode = 'learn'",
        vec![tls("192.0.2.10:443", "api.example.com")],
    );
    run_once(
        dir.path(),
        "mode = 'alert'",
        vec![
            tls("192.0.2.10:443", "api.example.com"),
            tls("192.0.2.12:443", "docs.example.com"),
        ],
    );
    let state = scribe_tests::sqlite_store(&dir.path().join("state.db"));
    let api = futures_block(state.get_host("api.example.com"))
        .unwrap()
        .unwrap();
    assert_eq!((api.conn_count, api.bytes_out), (2, 200));
    let events = stored(dir.path());
    assert_eq!(
        alerts_for(&events, "api.example.com"),
        0,
        "learned in the first run"
    );
    assert_eq!(alerts_for(&events, "docs.example.com"), 1);
}

/// SCN-25: a host learned in one profile is unlisted in another.
#[test]
fn profiles_are_isolated() {
    let dir = tempfile::tempdir().unwrap();
    run_once(
        dir.path(),
        "mode = 'learn'\nprofile = 'work'",
        vec![tls("192.0.2.10:443", "api.example.com")],
    );
    run_once(
        dir.path(),
        "mode = 'alert'\nprofile = 'home'",
        vec![tls("192.0.2.10:443", "api.example.com")],
    );
    run_once(
        dir.path(),
        "mode = 'alert'\nprofile = 'work'",
        vec![tls("192.0.2.10:443", "api.example.com")],
    );
    assert_eq!(
        alerts_for(&stored(dir.path()), "api.example.com"),
        1,
        "only the home run alerts"
    );
}
