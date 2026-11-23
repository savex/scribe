//! The real `scribe` against `MockApiServer` playing the UI's mock scenarios: what people see for
//! each situation the UI is designed for, without a daemon.

use std::path::Path;
use std::process::Output;

use scribe_test_support::{MockApiServer, Scenario};

const SCRIBE: &str = env!("CARGO_BIN_EXE_scribe-under-test");

fn scenario(name: &str) -> Scenario {
    Scenario::named(&scribe_tests::repo_root(), name).unwrap()
}

async fn scribe(socket: &Path, args: &[&str]) -> Output {
    let socket = socket.to_owned();
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(SCRIBE)
            .args(&args)
            .env("SCRIBE_SOCKET", &socket)
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

fn out(o: &Output, code: i32) -> (String, String) {
    let (stdout, stderr) = (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    );
    assert_eq!(
        o.status.code(),
        Some(code),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    (stdout, stderr)
}

/// Serves `name` in a temp dir for the length of `body`.
async fn with_mock<F, Fut>(name: &str, body: F)
where
    F: FnOnce(std::path::PathBuf) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let server = MockApiServer::start(scenario(name), &socket).unwrap();
    body(socket).await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn typical_day() {
    with_mock("typical", |s| async move {
        let (status, _) = out(&scribe(&s, &["status"]).await, 0);
        let lines: Vec<&str> = status.lines().collect();
        assert!(lines[0].contains("running"), "{status}");
        assert!(
            lines[1].starts_with("! sink_spooling"),
            "critical first: {status}"
        );
        let (hosts, _) = out(&scribe(&s, &["hosts"]).await, 0);
        assert!(hosts.ends_with("5 hosts\n"), "{hosts}");
        let (alerts, _) = out(&scribe(&s, &["alerts"]).await, 0);
        assert!(
            alerts.contains("    url: http://plain.example.com/"),
            "{alerts}"
        );
        let (health, _) = out(&scribe(&s, &["daemon", "health"]).await, 0);
        assert!(health.starts_with("degraded: "), "{health}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn first_launch_in_learn_mode() {
    with_mock("empty-first-launch", |s| async move {
        let (status, _) = out(&scribe(&s, &["status"]).await, 0);
        assert!(status.contains("mode       learn"), "{status}");
        assert!(
            status.contains("learn      ends 2023-11-21T22:13:20Z"),
            "{status}"
        );
        assert_eq!(out(&scribe(&s, &["alerts"]).await, 0).0, "no alerts\n");
        assert_eq!(
            out(&scribe(&s, &["daemon", "health"]).await, 0).0,
            "healthy\n"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hibernating_on_purpose() {
    with_mock("hibernating", |s| async move {
        let (status, _) = out(&scribe(&s, &["status"]).await, 0);
        assert!(
            status.contains(
                "hibernate  since 2023-11-15T09:00:00Z until 2023-11-15T10:00:00Z, by root"
            ),
            "{status}"
        );
        let (woke, _) = out(&scribe(&s, &["daemon", "wakeup"]).await, 0);
        assert_eq!(woke, "running\n");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn degraded_with_drops_and_a_failed_module() {
    with_mock("degraded-drops", |s| async move {
        let (status, _) = out(&scribe(&s, &["status"]).await, 0);
        let critical: Vec<&str> = status.lines().filter(|l| l.starts_with("! ")).collect();
        assert_eq!(critical.len(), 3, "{status}");
        assert!(
            status.contains("sensor     pcap, no process info, fallback"),
            "{status}"
        );
    })
    .await;
    with_mock("module-failed", |s| async move {
        let (modules, _) = out(&scribe(&s, &["modules"]).await, 0);
        assert!(modules.contains("failed"), "{modules}");
        let (health, _) = out(&scribe(&s, &["daemon", "health", "--json"]).await, 0);
        assert!(health.contains("\"degraded\""), "{health}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_newer_daemon_is_flagged() {
    with_mock("version-mismatch", |s| async move {
        let (_, stderr) = out(&scribe(&s, &["status"]).await, 0);
        assert!(stderr.contains("scribed speaks API version 99"), "{stderr}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn many_hosts_page_and_filter() {
    with_mock("many-hosts", |s| async move {
        let (json, _) = out(
            &scribe(&s, &["hosts", "--json", "--filter", "host-9999."]).await,
            0,
        );
        let page: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(page["total"], 1);
        assert_eq!(page["items"][0]["name"], "host-9999.load.example.com");
    })
    .await;
    let all = scenario("many-hosts");
    assert_eq!(all.hosts.len(), 10_000);
    let listed = all.hosts.iter().filter(|h| h.on_list).count();
    assert!(
        (8_500..9_500).contains(&listed),
        "about 90% listed: {listed}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_down_daemon_is_reported() {
    assert!(scenario("daemon-down").refuses_connections);
    let dir = tempfile::tempdir().unwrap();
    let (_, stderr) = out(&scribe(&dir.path().join("api.sock"), &["status"]).await, 1);
    assert!(stderr.contains("scribed is not running"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn control_commands_change_the_mock() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let server = MockApiServer::start(scenario("typical"), &socket).unwrap();
    assert_eq!(
        out(&scribe(&socket, &["mode", "alert"]).await, 0).0,
        "mode: caution -> alert\n"
    );
    out(
        &scribe(&socket, &["baseline", "add", "new.example.net"]).await,
        0,
    );
    out(&scribe(&socket, &["alerts", "ack", "2"]).await, 0);
    let state = server.scenario();
    assert_eq!(state.status.mode, "alert");
    assert!(state
        .baseline
        .entries
        .iter()
        .any(|e| e.host == "new.example.net"));
    assert!(
        state
            .alerts
            .iter()
            .find(|a| a.id == 2)
            .unwrap()
            .acknowledged
    );
    server.stop().await;
}
