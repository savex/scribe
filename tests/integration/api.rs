//! INT-11: the local API on a running daemon. `serve_full` with a fake sensor and SQLite storage,
//! the API on a socket in a temp dir, and a real client.

use std::path::{Path, PathBuf};
use std::time::Duration;

use scribe_api::pb::scribe_client::ScribeClient;
use scribe_api::pb::{self, health_reply::Level};
use scribe_api::unix::{self, ServerCheck};
use scribe_core::platform::DefaultPaths;
use scribe_core::{FlowKind, Observation, Security};
use scribe_daemon::app::{serve_full, Command, ServeOptions};
use scribe_daemon::config::{context, parse, resolve, HostFacts, Settings, Source};
use scribe_test_support::packets::tls::client_hello_sni;
use scribe_test_support::{flow, FakeSensor};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;
use tonic::transport::Channel;

const WAIT: Duration = Duration::from_secs(10);

pub(crate) fn config_text(dir: &Path, mode: &str, extra: &str) -> String {
    format!(
        "mode = '{mode}'\ndata_dir = '{}'\n{extra}\n[log]\nfile = ''\n",
        dir.display()
    )
}

/// Settings from `dir/scribe.toml`, written first, so a reload reads the same file.
pub(crate) fn settings_with(dir: &Path, mode: &str, extra: &str) -> Settings {
    let path = dir.join("scribe.toml");
    let text = config_text(dir, mode, extra);
    std::fs::write(&path, &text).unwrap();
    let source = Source::File(path);
    resolve(
        parse(&text, &source, &context()).unwrap(),
        source,
        &DefaultPaths::current().unwrap(),
        &HostFacts,
    )
    .unwrap()
}

pub(crate) fn settings(dir: &Path, mode: &str) -> Settings {
    settings_with(dir, mode, "")
}

/// `[api]` naming a group the test user is in, so control calls are allowed.
pub(crate) fn my_admin_group() -> String {
    // SAFETY: getuid / getgid have no preconditions.
    let me = scribe_api::unix::identify(unsafe { libc::getuid() }, unsafe { libc::getgid() }, None);
    format!("[api]\nadmin_group = '{}'", me.groups[0])
}

pub(crate) fn is_root() -> bool {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() == 0 }
}

/// A TLS flow to a named host and a raw-IP flow (an alert in caution mode).
pub(crate) fn two_flows() -> Vec<Observation> {
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
    vec![tls, raw]
}

pub(crate) struct Daemon {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) socket: PathBuf,
    commands: mpsc::Sender<Command>,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Daemon {
    pub(crate) async fn start(mode: &str, observations: Vec<Observation>) -> Self {
        Self::start_with(mode, "", observations).await
    }

    pub(crate) async fn start_with(
        mode: &str,
        extra: &str,
        observations: Vec<Observation>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("run/api.sock");
        let (commands, rx) = mpsc::channel(8);
        let (stop, stopped) = oneshot::channel::<()>();
        let options = ServeOptions {
            commands: Some(rx),
            api_socket: Some(socket.clone()),
        };
        let task = tokio::spawn(serve_full(
            settings_with(dir.path(), mode, extra),
            Box::new(FakeSensor::from_observations(observations)),
            options,
            async {
                let _ = stopped.await;
            },
        ));
        let deadline = tokio::time::Instant::now() + WAIT;
        while !socket.exists() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the API socket never appeared"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Self {
            dir,
            socket,
            commands,
            stop: Some(stop),
            task,
        }
    }

    pub(crate) async fn client(&self) -> ScribeClient<Channel> {
        unix::connect(
            &self.socket,
            ServerCheck::RootOrSelf,
            Duration::from_secs(5),
        )
        .await
        .unwrap()
    }

    async fn hibernate(&self) {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Hibernate {
                for_: Some(Duration::from_secs(600)),
                caller: "test".into(),
                reply,
            })
            .await
            .unwrap();
        answer.await.unwrap();
    }

    /// Stops scribed and hands back its folder (storage stays readable).
    pub(crate) async fn stop(mut self) -> tempfile::TempDir {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(WAIT, self.task)
            .await
            .expect("scribed stops")
            .unwrap()
            .unwrap();
        self.dir
    }
}

/// Every audit message stored in `dir`'s event history.
pub(crate) async fn audits(dir: &Path) -> Vec<String> {
    use scribe_storage_api::{EventQuery, EventSink, StoredEvent};
    let sink = scribe_tests::sqlite_sink("local-history", &dir.join("events.db"));
    sink.query(&EventQuery::default())
        .await
        .unwrap()
        .items
        .into_iter()
        .filter_map(|e| match e {
            StoredEvent::Audit(a) => Some(a.message),
            _ => None,
        })
        .collect()
}

pub(crate) fn has(audits: &[String], part: &str) -> bool {
    audits.iter().any(|m| m.contains(part))
}

/// Polls `get` until `done` holds for its value.
pub(crate) async fn eventually<T, F, Fut>(mut get: F, done: impl Fn(&T) -> bool) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let value = get().await;
        if done(&value) {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition never held"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn read_calls_report_status_hosts_alerts_baseline_and_modules() {
    let daemon = Daemon::start("caution", two_flows()).await;
    let mut client = daemon.client().await;

    let status = eventually(
        || {
            let mut c = client.clone();
            async move {
                c.get_status(pb::StatusRequest {})
                    .await
                    .unwrap()
                    .into_inner()
            }
        },
        |s| s.counters.as_ref().is_some_and(|c| c.flows == 2),
    )
    .await;
    assert_eq!(status.api_version, scribe_api::API_VERSION);
    assert_eq!(status.daemon_version, scribe_core::VERSION);
    assert_eq!(status.run_state, "running");
    assert_eq!(
        (status.mode.as_str(), status.profile.as_str()),
        ("caution", "default")
    );
    assert!(
        status.config_path.ends_with("scribe.toml"),
        "{}",
        status.config_path
    );
    let sensor = status.sensor.unwrap();
    assert_eq!((sensor.health.as_str(), sensor.process_info), ("ok", true));
    let storage = status.storage.unwrap();
    assert_eq!(storage.state.unwrap().kind, "sqlite");
    assert!(storage
        .sinks
        .iter()
        .any(|s| s.name == "local-history" && s.health == "ok"));
    assert_eq!(status.counters.unwrap().alerts, 1);
    assert!(status.critical.is_empty(), "{:?}", status.critical);

    let health = client
        .health(pb::HealthRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(health.level, Level::Healthy as i32, "{:?}", health.reasons);

    let hosts = client
        .list_hosts(pb::ListHostsRequest::default())
        .await
        .unwrap()
        .into_inner();
    let api = hosts
        .items
        .iter()
        .find(|h| h.name == "api.example.com")
        .unwrap();
    assert!(api.tls_seen && !api.unresolved && !api.on_list);
    assert_eq!((api.conn_count, api.bytes_out), (1, 512));
    assert_eq!(api.processes, ["/usr/bin/curl"]);
    let raw = hosts
        .items
        .iter()
        .find(|h| h.name == "198.51.100.7")
        .unwrap();
    assert!(raw.unresolved);
    let filtered = client
        .list_hosts(pb::ListHostsRequest {
            name_contains: "example".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(filtered.items.len(), 1);

    let alerts = eventually(
        || {
            let mut c = client.clone();
            async move {
                c.list_alerts(pb::ListAlertsRequest::default())
                    .await
                    .unwrap()
                    .into_inner()
            }
        },
        |page| !page.items.is_empty(),
    )
    .await;
    let alert = &alerts.items[0];
    assert_eq!(alert.reason, "raw_ip");
    assert_eq!(alert.dst, "198.51.100.7:8443");
    assert_eq!(alert.process_path.as_deref(), Some("/opt/agent/bin/agent"));
    assert!(alert.id > 0, "sealed alerts carry their chain sequence");
    assert!(!alert.acknowledged);

    let baseline = client
        .get_baseline(pb::GetBaselineRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(baseline.profile, "default");
    assert!(baseline.entries.is_empty(), "caution mode learns nothing");

    let exported: Vec<pb::ExportItem> = client
        .export(pb::ExportRequest {})
        .await
        .unwrap()
        .into_inner()
        .map(Result::unwrap)
        .collect()
        .await;
    let names: Vec<&str> = exported
        .iter()
        .filter_map(|i| match &i.item {
            Some(pb::export_item::Item::Host(h)) => Some(h.name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");

    let modules = client
        .list_modules(pb::ListModulesRequest {})
        .await
        .unwrap()
        .into_inner();
    let url = modules.items.iter().find(|m| m.id == "url").unwrap();
    assert!(url.enabled);
    assert_eq!((url.state.as_str(), url.health.as_str()), ("running", "ok"));
    let missing = client
        .get_module(pb::GetModuleRequest { id: "kperf".into() })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn learn_mode_baseline_is_listed_and_exported() {
    let daemon = Daemon::start("learn", two_flows()).await;
    let mut client = daemon.client().await;
    let baseline = eventually(
        || {
            let mut c = client.clone();
            async move {
                c.get_baseline(pb::GetBaselineRequest::default())
                    .await
                    .unwrap()
                    .into_inner()
            }
        },
        |b| b.entries.len() == 2,
    )
    .await;
    assert!(baseline.entries.iter().all(|e| e.source == "learned"));
    let hosts = client
        .list_hosts(pb::ListHostsRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert!(hosts.items.iter().all(|h| h.on_list), "{:?}", hosts.items);
    let exported: Vec<pb::ExportItem> = client
        .export(pb::ExportRequest {})
        .await
        .unwrap()
        .into_inner()
        .map(Result::unwrap)
        .collect()
        .await;
    let entries = exported
        .iter()
        .filter(|i| matches!(i.item, Some(pb::export_item::Item::BaselineEntry(_))))
        .count();
    assert_eq!(entries, 2);
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hibernation_shows_in_status_health_and_the_alert_stream() {
    let daemon = Daemon::start("caution", vec![]).await;
    let mut client = daemon.client().await;
    let mut alerts = client
        .watch_alerts(pb::WatchAlertsRequest {})
        .await
        .unwrap()
        .into_inner();
    daemon.hibernate().await;

    let alert = tokio::time::timeout(WAIT, alerts.next())
        .await
        .expect("the hibernated alert arrives")
        .unwrap()
        .unwrap();
    assert_eq!(alert.reason, "hibernated");
    assert_eq!(alert.dst, "0.0.0.0:0");

    let status = client
        .get_status(pb::StatusRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(status.run_state, "hibernating");
    assert_eq!(status.hibernated_by, "test");
    assert!(status.hibernating_until_ms.unwrap() > status.hibernating_since_ms.unwrap());
    assert_eq!(status.sensor.unwrap().health, "detached");
    let kinds: Vec<&str> = status.critical.iter().map(|c| c.kind.as_str()).collect();
    assert_eq!(
        kinds,
        ["hibernating"],
        "a detached sensor is expected while hibernating"
    );

    let health = client
        .health(pb::HealthRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(health.level, Level::Degraded as i32);
    assert!(
        health.reasons[0].contains("hibernating since"),
        "{:?}",
        health.reasons
    );

    let socket = daemon.socket.clone();
    daemon.stop().await;
    let end = tokio::time::timeout(WAIT, alerts.next())
        .await
        .expect("the stream ends");
    assert!(
        !matches!(end, Some(Ok(_))),
        "no more alerts after shutdown: {end:?}"
    );
    assert!(!socket.exists(), "the socket is removed at shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_standard_health_service_answers() {
    use tonic_health::pb::health_check_response::ServingStatus;
    use tonic_health::pb::health_client::HealthClient;
    use tonic_health::pb::HealthCheckRequest;

    let daemon = Daemon::start("caution", vec![]).await;
    let channel = unix::channel(
        &daemon.socket,
        ServerCheck::RootOrSelf,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let health = HealthClient::new(channel);
    for service in ["", "scribe.v1.Scribe"] {
        let reply = eventually(
            || {
                let mut h = health.clone();
                let service = service.to_owned();
                async move { h.check(HealthCheckRequest { service }).await }
            },
            |r| {
                r.as_ref()
                    .is_ok_and(|r| r.get_ref().status == ServingStatus::Serving as i32)
            },
        )
        .await;
        assert!(reply.is_ok());
    }
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn control_calls_change_mode_baseline_and_acknowledge_alerts() {
    let daemon = Daemon::start_with("caution", &my_admin_group(), two_flows()).await;
    let mut client = daemon.client().await;
    let alerts = eventually(
        || {
            let mut c = client.clone();
            async move {
                c.list_alerts(pb::ListAlertsRequest::default())
                    .await
                    .unwrap()
                    .into_inner()
            }
        },
        |page| !page.items.is_empty(),
    )
    .await;
    let id = alerts.items[0].id;

    let mode = client
        .set_mode(pb::SetModeRequest {
            mode: "alert".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (mode.previous.as_str(), mode.mode.as_str()),
        ("caution", "alert")
    );
    let status = client
        .get_status(pb::StatusRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(status.mode, "alert");
    let bad = client
        .set_mode(pb::SetModeRequest {
            mode: "paranoid".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(bad.code(), tonic::Code::InvalidArgument);

    let edit = client
        .edit_baseline(pb::EditBaselineRequest {
            add: vec!["API.Example.com.".into(), "new.example.net".into()],
            remove: vec!["absent.example".into()],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(edit.added, ["api.example.com", "new.example.net"]);
    assert_eq!(edit.unchanged, ["absent.example"]);
    let edit = client
        .edit_baseline(pb::EditBaselineRequest {
            add: vec!["api.example.com".into()],
            remove: vec!["new.example.net".into()],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (edit.removed, edit.unchanged),
        (
            vec!["new.example.net".to_owned()],
            vec!["api.example.com".to_owned()]
        )
    );
    let baseline = client
        .get_baseline(pb::GetBaselineRequest::default())
        .await
        .unwrap()
        .into_inner();
    let hosts: Vec<(&str, &str)> = baseline
        .entries
        .iter()
        .map(|e| (e.host.as_str(), e.source.as_str()))
        .collect();
    assert_eq!(hosts, [("api.example.com", "manual")]);
    let listed = client
        .list_hosts(pb::ListHostsRequest {
            name_contains: "api.example".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(listed.items[0].on_list);
    for name in ["a b", "", "evil.example/path"] {
        let err = client
            .edit_baseline(pb::EditBaselineRequest {
                add: vec![name.into()],
                remove: vec![],
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{name:?}");
    }

    let ack = client
        .ack_alert(pb::AckAlertRequest { id })
        .await
        .unwrap()
        .into_inner();
    assert!(ack.changed);
    let again = client
        .ack_alert(pb::AckAlertRequest { id })
        .await
        .unwrap()
        .into_inner();
    assert!(!again.changed, "acknowledging twice changes nothing");
    let listed = client
        .list_alerts(pb::ListAlertsRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert!(
        listed
            .items
            .iter()
            .find(|a| a.id == id)
            .unwrap()
            .acknowledged
    );
    let missing = client
        .ack_alert(pb::AckAlertRequest { id: 999_999 })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);

    let dir = daemon.stop().await;
    let audits = audits(dir.path()).await;
    assert!(
        has(&audits, "mode set to alert (was caution) by "),
        "{audits:#?}"
    );
    assert!(has(&audits, "uid "), "callers carry their ids: {audits:#?}");
    assert!(
        has(&audits, "added [api.example.com, new.example.net]"),
        "{audits:#?}"
    );
    assert!(has(&audits, "removed [new.example.net]"), "{audits:#?}");
    assert!(
        has(
            &audits,
            &format!("alert {id} (raw_ip to 198.51.100.7) acknowledged by")
        ),
        "{audits:#?}"
    );
    assert!(has(&audits, "(already acknowledged)"), "{audits:#?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn control_calls_outside_the_admin_group_are_refused_and_audited() {
    let daemon = Daemon::start_with(
        "caution",
        "[api]\nadmin_group = 'scribe-test-no-such-group'",
        vec![],
    )
    .await;
    let mut client = daemon.client().await;
    let mode = client
        .set_mode(pb::SetModeRequest {
            mode: "alert".into(),
        })
        .await;
    let hibernate = client
        .hibernate(pb::HibernateRequest { for_s: Some(60) })
        .await;
    let reset = client.reset(pb::ResetRequest::default()).await;
    // Read calls stay open.
    let status = client
        .get_status(pb::StatusRequest {})
        .await
        .unwrap()
        .into_inner();
    if is_root() {
        mode.unwrap();
        hibernate.unwrap();
        reset.unwrap();
        daemon.stop().await;
        return;
    }
    for err in [
        mode.unwrap_err(),
        hibernate.unwrap_err(),
        reset.unwrap_err(),
    ] {
        assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err}");
        assert!(err.message().contains("scribe-test-no-such-group"), "{err}");
    }
    assert_eq!(
        (status.mode.as_str(), status.run_state.as_str()),
        ("caution", "running")
    );
    let dir = daemon.stop().await;
    let audits = audits(dir.path()).await;
    for call in ["SetMode", "Hibernate", "Reset"] {
        assert!(
            has(&audits, &format!("refused {call} from ")),
            "{call}: {audits:#?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_reload_hibernate_and_wakeup_through_the_api() {
    let extra = my_admin_group();
    let daemon = Daemon::start_with("caution", &extra, two_flows()).await;
    let mut client = daemon.client().await;
    eventually(
        || {
            let mut c = client.clone();
            async move {
                c.get_status(pb::StatusRequest {})
                    .await
                    .unwrap()
                    .into_inner()
            }
        },
        |s| s.counters.as_ref().is_some_and(|c| c.flows == 2),
    )
    .await;

    let reset = client
        .reset(pb::ResetRequest {
            counters: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reset.done, ["counters"]);
    assert_eq!(reset.status.unwrap().counters.unwrap().flows, 0);

    // A changed file: mode applies live, the sensor needs a restart.
    let path = daemon.dir.path().join("scribe.toml");
    let changed = config_text(
        daemon.dir.path(),
        "alert",
        &format!("{extra}\n[sensor]\ninterface = 'eth9'"),
    );
    std::fs::write(&path, changed).unwrap();
    let reload = client
        .reset(pb::ResetRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reload.done, ["config", "counters", "caches"]);
    assert_eq!(reload.applied, ["mode"]);
    assert_eq!(reload.needs_restart, ["sensor"]);
    assert_eq!(reload.status.unwrap().mode, "alert");

    std::fs::write(&path, "mode = 'paranoid'\n").unwrap();
    let err = client
        .reset(pb::ResetRequest {
            config: true,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("running config stays"), "{err}");
    assert!(err.message().contains("line 1"), "{err}");

    let zero = client
        .hibernate(pb::HibernateRequest { for_s: Some(0) })
        .await
        .unwrap_err();
    assert_eq!(zero.code(), tonic::Code::InvalidArgument);
    let status = client
        .hibernate(pb::HibernateRequest { for_s: Some(600) })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(status.run_state, "hibernating");
    assert!(
        status.hibernated_by.contains("uid "),
        "{}",
        status.hibernated_by
    );
    let first_until = status.hibernating_until_ms.unwrap();
    let status = client
        .hibernate(pb::HibernateRequest { for_s: Some(60) })
        .await
        .unwrap()
        .into_inner();
    assert!(
        status.hibernating_until_ms.unwrap() < first_until,
        "a second hibernate sets a new end"
    );
    let status = client
        .wakeup(pb::WakeupRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(status.run_state, "running");
    let status = client
        .wakeup(pb::WakeupRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        status.run_state, "running",
        "waking a running daemon is fine"
    );

    let dir = daemon.stop().await;
    let audits = audits(dir.path()).await;
    assert!(has(&audits, "runtime reset by "), "{audits:#?}");
    assert!(has(&audits, "config reloaded by "), "{audits:#?}");
    assert!(has(&audits, "hibernate by "), "{audits:#?}");
    assert!(has(&audits, "wakeup by "), "{audits:#?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_daemon_on_the_same_socket_runs_without_the_api() {
    let first = Daemon::start("caution", vec![]).await;
    let dir = tempfile::tempdir().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let second = tokio::spawn(serve_full(
        settings(dir.path(), "caution"),
        Box::new(FakeSensor::new(vec![])),
        ServeOptions {
            commands: None,
            api_socket: Some(first.socket.clone()),
        },
        async {
            let _ = stopped.await;
        },
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = stop.send(());
    tokio::time::timeout(WAIT, second)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // The first daemon's socket survives the second one's start and stop.
    first
        .client()
        .await
        .get_status(pb::StatusRequest {})
        .await
        .unwrap();
    first.stop().await;
}
