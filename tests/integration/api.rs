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

fn settings(dir: &Path, mode: &str) -> Settings {
    let text = format!(
        "mode = '{mode}'\ndata_dir = '{}'\n[log]\nfile = ''\n",
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

/// A TLS flow to a named host and a raw-IP flow (an alert in caution mode).
fn two_flows() -> Vec<Observation> {
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

struct Daemon {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    commands: mpsc::Sender<Command>,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Daemon {
    async fn start(mode: &str, observations: Vec<Observation>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("run/api.sock");
        let (commands, rx) = mpsc::channel(8);
        let (stop, stopped) = oneshot::channel::<()>();
        let options = ServeOptions {
            commands: Some(rx),
            api_socket: Some(socket.clone()),
        };
        let task = tokio::spawn(serve_full(
            settings(dir.path(), mode),
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
            _dir: dir,
            socket,
            commands,
            stop: Some(stop),
            task,
        }
    }

    async fn client(&self) -> ScribeClient<Channel> {
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

    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(WAIT, self.task)
            .await
            .expect("scribed stops")
            .unwrap()
            .unwrap();
    }
}

/// Polls `get` until `done` holds for its value.
async fn eventually<T, F, Fut>(mut get: F, done: impl Fn(&T) -> bool) -> T
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
    assert_eq!(status.config_path, "test.toml");
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
async fn control_calls_are_not_served_yet() {
    let daemon = Daemon::start("caution", vec![]).await;
    let err = daemon
        .client()
        .await
        .set_mode(pb::SetModeRequest {
            mode: "alert".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unimplemented);
    daemon.stop().await;
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
