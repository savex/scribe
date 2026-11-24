//! FUN-A03 `notification_adapters`: the `scribe notify` agent against `MockApiServer`, with a
//! fake notifier in place of the desktop.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use scribe_api::pb;
use scribe_cli::notify::{
    follow, notification, reason_title, summary, AgentOptions, AgentReport, Notification, Notifier,
};
use scribe_core::Clock;
use scribe_test_support::{FakeClock, MockApiServer, Scenario};
use tokio::sync::{mpsc, oneshot};

const WAIT: Duration = Duration::from_secs(10);

fn alert(id: u64, reason: &str, score: u32) -> pb::Alert {
    pb::Alert {
        id,
        ts_ms: 1_800_000_000_000 + id as i64,
        host: Some(format!("h{id}.example.com")),
        dst: "203.0.113.9:80".into(),
        process_path: Some("/usr/bin/curl".into()),
        score,
        reason: reason.into(),
        acknowledged: false,
        notes: [("url".to_owned(), format!("http://h{id}.example.com/"))].into(),
    }
}

#[test]
fn notification_text_names_the_host_process_url_and_ack_command() {
    let n = notification(&alert(7, "plaintext", 60));
    assert_eq!(n.title, "scribe: Unencrypted connection");
    assert_eq!(
        n.body,
        "h7.example.com (203.0.113.9:80)\nprocess /usr/bin/curl\nhttp://h7.example.com/\nscore 60 · scribe alerts ack 7"
    );
    let mut bare = alert(8, "raw_ip", 60);
    bare.host = None;
    bare.process_path = None;
    bare.notes.clear();
    assert_eq!(
        notification(&bare).body,
        "203.0.113.9:80\nscore 60 · scribe alerts ack 8"
    );
    assert_eq!(reason_title("url.secret_in_query"), "url.secret_in_query");
    assert_eq!(summary(4, 10).title, "scribe: 4 more alerts");
}

/// Reports shown notifications, and skipped alerts as `skipped <id>`, in the order they happen.
struct Fake(mpsc::UnboundedSender<Notification>);

impl Notifier for Fake {
    fn show(&mut self, n: &Notification) -> Result<(), String> {
        self.0.send(n.clone()).map_err(|e| e.to_string())
    }
    fn skipped(&mut self, alert: &pb::Alert) {
        let _ = self.0.send(Notification {
            title: format!("skipped {}", alert.id),
            body: String::new(),
        });
    }
}

struct Agent {
    shown: mpsc::UnboundedReceiver<Notification>,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<AgentReport>,
}

impl Agent {
    fn start(socket: &Path, options: AgentOptions, clock: Arc<dyn Clock>) -> Self {
        let (tx, shown) = mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel::<()>();
        let socket = socket.to_owned();
        let task = tokio::spawn(async move {
            let mut fake = Fake(tx);
            follow(&socket, &mut fake, &options, clock, async {
                let _ = stopped.await;
            })
            .await
            .unwrap()
        });
        Self { shown, stop, task }
    }

    async fn next(&mut self) -> Notification {
        tokio::time::timeout(WAIT, self.shown.recv())
            .await
            .expect("a notification")
            .unwrap()
    }

    async fn stop(self) -> AgentReport {
        let _ = self.stop.send(());
        self.task.await.unwrap()
    }
}

fn empty() -> Scenario {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    Scenario::named(&root, "empty-first-launch").unwrap()
}

async fn watched(server: &MockApiServer) {
    tokio::time::timeout(WAIT, async {
        while server.watchers() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the agent subscribes");
}

fn quick(max_per_minute: u32, min_score: u32) -> AgentOptions {
    AgentOptions {
        max_per_minute,
        min_score,
        backoff: Duration::from_millis(50),
        max_backoff: Duration::from_millis(200),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn notify_agent_shows_alerts_and_rate_limits_them() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let server = MockApiServer::start(empty(), &socket).unwrap();
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let mut agent = Agent::start(&socket, quick(2, 0), clock.clone());
    watched(&server).await;

    for id in 1..=4 {
        server.raise(alert(id, "unlisted_host", 100));
    }
    assert_eq!(agent.next().await.title, "scribe: New host");
    assert!(agent.next().await.body.starts_with("h2.example.com"));
    assert_eq!(agent.next().await.title, "skipped 3");
    assert_eq!(agent.next().await.title, "skipped 4");
    clock.advance(Duration::from_secs(60));
    let held = agent.next().await;
    assert_eq!(held.title, "scribe: 2 more alerts");

    let report = agent.stop().await;
    assert_eq!(report.shown, 2);
    assert_eq!(report.suppressed, 2);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn notify_agent_skips_low_scores_but_never_hibernation() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let server = MockApiServer::start(empty(), &socket).unwrap();
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    let mut agent = Agent::start(&socket, quick(0, 50), clock);
    watched(&server).await;

    server.raise(alert(1, "unusual_port", 30));
    server.raise(alert(2, "hibernated", 0));
    server.raise(alert(3, "threat_list", 90));
    assert_eq!(agent.next().await.title, "skipped 1");
    assert_eq!(agent.next().await.title, "scribe: scribed is hibernating");
    assert_eq!(agent.next().await.title, "scribe: Host on a threat list");
    let report = agent.stop().await;
    assert_eq!((report.shown, report.below_min_score), (2, 1));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn notify_agent_waits_for_scribed_and_catches_up_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let clock = Arc::new(FakeClock::at_unix(1_800_000_000));
    // Started before scribed: it waits.
    let mut agent = Agent::start(&socket, quick(0, 0), clock);
    tokio::time::sleep(Duration::from_millis(120)).await;

    let server = MockApiServer::start(empty(), &socket).unwrap();
    watched(&server).await;
    server.raise(alert(1, "unlisted_host", 100));
    assert!(agent.next().await.body.starts_with("h1.example.com"));
    let mut state = server.scenario();
    server.stop().await;

    // Raised while the agent was away; alert 1 must not show again.
    state.alerts.push(alert(2, "plaintext", 60));
    let server = MockApiServer::start(state, &socket).unwrap();
    let caught_up = agent.next().await;
    assert!(
        caught_up.body.starts_with("h2.example.com"),
        "{caught_up:?}"
    );
    watched(&server).await;
    server.raise(alert(3, "raw_ip", 60));
    assert!(agent.next().await.body.starts_with("h3.example.com"));

    let report = agent.stop().await;
    assert_eq!(report.shown, 3);
    assert_eq!(report.connections, 2);
    server.stop().await;
}
