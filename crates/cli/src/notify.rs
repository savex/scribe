//! `scribe notify`: the desktop-notification agent (phase 11). scribed runs as a system service,
//! which can't post to a desktop session on any of the three systems, so this agent runs in the
//! user's session (started at login, see `packaging/*/scribe-notify*`), follows the API's alert
//! stream and shows one notification per alert.
//!
//! - Rate limit: `--max-per-minute` per agent ([`Throttle`]); the rest become one summary
//!   notification when the minute ends.
//! - scribed not running or restarting: the agent waits and reconnects (1 s doubling to 60 s), and
//!   after a reconnect shows the alerts raised while it was away, by alert id. It stops only on
//!   errors that waiting won't fix (permission denied, a server that fails the identity check).

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use scribe_alerts::{Admit, Throttle};
use scribe_api::pb;
use scribe_api::TransportError;
use scribe_core::Clock;
use tokio_stream::StreamExt;

use crate::client::{call_failure, transport_failure, Failure, CALL_TIMEOUT};

/// One desktop notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub title: String,
    pub body: String,
}

/// Where notifications go: the desktop ([`DesktopNotifier`]) or a test double.
pub trait Notifier: Send {
    fn show(&mut self, notification: &Notification) -> Result<(), String>;
    /// An alert that was not shown (rate limit or `--min-score`); nothing to do by default.
    fn skipped(&mut self, alert: &pb::Alert) {
        let _ = alert;
    }
}

/// What a reason means to someone reading a notification.
pub fn reason_title(reason: &str) -> String {
    match reason {
        "unlisted_host" => "New host".into(),
        "plaintext" => "Unencrypted connection".into(),
        "raw_ip" => "Connection to a bare IP address".into(),
        "unusual_port" => "Unusual port".into(),
        "high_entropy" => "Random-looking host name".into(),
        "new_tld" => "New top-level domain".into(),
        "new_process" => "New process".into(),
        "threat_list" => "Host on a threat list".into(),
        "hibernated" => "scribed is hibernating".into(),
        other => other.to_owned(),
    }
}

/// The notification for one alert.
pub fn notification(alert: &pb::Alert) -> Notification {
    let mut lines = Vec::new();
    match &alert.host {
        Some(host) => lines.push(format!("{host} ({})", alert.dst)),
        None => lines.push(alert.dst.clone()),
    }
    if let Some(process) = &alert.process_path {
        lines.push(format!("process {process}"));
    }
    if let Some(url) = alert.notes.get("url") {
        lines.push(url.clone());
    }
    lines.push(format!(
        "score {} · scribe alerts ack {}",
        alert.score, alert.id
    ));
    Notification {
        title: format!("scribe: {}", reason_title(&alert.reason)),
        body: lines.join("\n"),
    }
}

/// The notification for alerts the rate limit held back.
pub fn summary(count: u64, max_per_minute: u32) -> Notification {
    Notification {
        title: format!("scribe: {count} more alerts"),
        body: format!(
            "Not shown one by one (at most {max_per_minute} a minute). Run `scribe alerts` to see them."
        ),
    }
}

/// Settings of one agent run.
#[derive(Debug, Clone)]
pub struct AgentOptions {
    /// `0` = unlimited.
    pub max_per_minute: u32,
    /// Alerts with a lower score are not shown (`hibernated` always is).
    pub min_score: u32,
    /// First wait before reconnecting; doubles up to [`AgentOptions::max_backoff`].
    pub backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for AgentOptions {
    fn default() -> Self {
        Self {
            max_per_minute: 10,
            min_score: 0,
            backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
        }
    }
}

/// What the agent did, for the exit message and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentReport {
    pub shown: u64,
    pub suppressed: u64,
    pub below_min_score: u64,
    pub connections: u64,
}

struct Agent<'a, N: Notifier> {
    notifier: &'a mut N,
    options: &'a AgentOptions,
    clock: Arc<dyn Clock>,
    throttle: Throttle,
    last_id: Option<u64>,
    last_ts_ms: i64,
    failing: bool,
    report: AgentReport,
}

impl<N: Notifier> Agent<'_, N> {
    fn handle(&mut self, alert: &pb::Alert) {
        if self.last_id.is_some_and(|last| alert.id <= last) {
            return;
        }
        self.last_id = Some(alert.id);
        self.last_ts_ms = self.last_ts_ms.max(alert.ts_ms);
        if alert.score < self.options.min_score && alert.reason != "hibernated" {
            self.report.below_min_score += 1;
            self.notifier.skipped(alert);
            return;
        }
        self.roll();
        match self.throttle.admit(self.clock.now()) {
            Admit::Send => {
                self.report.shown += 1;
                self.show(&notification(alert));
            }
            Admit::Suppress => {
                self.report.suppressed += 1;
                self.notifier.skipped(alert);
            }
        }
    }

    fn roll(&mut self) {
        if let Some(held) = self.throttle.roll(self.clock.now()) {
            self.show(&summary(held, self.options.max_per_minute));
        }
    }

    fn show(&mut self, n: &Notification) {
        match self.notifier.show(n) {
            Ok(()) => self.failing = false,
            Err(e) if !self.failing => {
                self.failing = true;
                eprintln!("scribe notify: cannot show a notification: {e}");
            }
            Err(_) => {}
        }
    }
}

/// Whether waiting could fix a connection error.
fn is_lasting(e: &TransportError) -> bool {
    match e {
        TransportError::Io { source, .. } => source.kind() == std::io::ErrorKind::PermissionDenied,
        TransportError::Refused(_) => true,
        TransportError::Connect(_) => false,
    }
}

/// Follow scribed's alerts until `stop` resolves (Ctrl-C in the CLI).
pub async fn follow<N: Notifier>(
    socket: &Path,
    notifier: &mut N,
    options: &AgentOptions,
    clock: Arc<dyn Clock>,
    stop: impl Future<Output = ()>,
) -> Result<AgentReport, Failure> {
    let mut agent = Agent {
        notifier,
        options,
        throttle: Throttle::new(options.max_per_minute),
        clock,
        last_id: None,
        last_ts_ms: 0,
        failing: false,
        report: AgentReport::default(),
    };
    tokio::pin!(stop);
    let mut backoff = options.backoff;
    let mut waiting_said = false;
    loop {
        let session = session(socket, &mut agent, &mut waiting_said, &mut backoff);
        tokio::select! {
            _ = &mut stop => return Ok(agent.report),
            ended = session => ended?,
        }
        tokio::select! {
            _ = &mut stop => return Ok(agent.report),
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(options.max_backoff);
    }
}

/// One connection: subscribe, catch up after a reconnect, then show alerts until the stream ends.
/// `Ok` = try again later; `Err` = give up.
async fn session<N: Notifier>(
    socket: &Path,
    agent: &mut Agent<'_, N>,
    waiting_said: &mut bool,
    backoff: &mut Duration,
) -> Result<(), Failure> {
    let mut client = match scribe_api::transport::connect(
        socket,
        scribe_api::ServerCheck::RootOrSelf,
        CALL_TIMEOUT,
    )
    .await
    {
        Ok(c) => c,
        Err(e) if is_lasting(&e) => return Err(transport_failure(socket, e)),
        Err(e) => {
            if !*waiting_said {
                *waiting_said = true;
                eprintln!(
                    "scribe notify: {}; waiting for scribed",
                    transport_failure(socket, e).message
                );
            }
            return Ok(());
        }
    };
    let mut stream = match client.watch_alerts(pb::WatchAlertsRequest {}).await {
        Ok(r) => r.into_inner(),
        Err(s) if s.code() == tonic::Code::PermissionDenied => return Err(call_failure(s)),
        Err(_) => return Ok(()),
    };
    agent.report.connections += 1;
    if *waiting_said || agent.report.connections > 1 {
        eprintln!("scribe notify: following scribed's alerts");
    }
    *waiting_said = false;
    *backoff = agent.options.backoff;
    if agent.last_id.is_some() {
        // Alerts raised while the agent was away (subscribed first, so none fall in between).
        if let Ok(page) = client
            .list_alerts(pb::ListAlertsRequest {
                since_ms: Some(agent.last_ts_ms),
                ..Default::default()
            })
            .await
        {
            let mut missed = page.into_inner().items;
            missed.sort_by_key(|a| a.id);
            for alert in &missed {
                agent.handle(alert);
            }
        }
    }
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            item = stream.next() => match item {
                Some(Ok(alert)) => agent.handle(&alert),
                Some(Err(_)) | None => {
                    eprintln!("scribe notify: scribed went away; waiting for it to come back");
                    *waiting_said = true;
                    return Ok(());
                }
            },
            _ = tick.tick() => agent.roll(),
        }
    }
}

/// Native notifications through `notify-rust` (D-Bus on Linux, Notification Center on macOS,
/// toasts on Windows).
#[cfg(feature = "notify")]
#[derive(Debug, Default)]
pub struct DesktopNotifier;

#[cfg(feature = "notify")]
impl Notifier for DesktopNotifier {
    fn show(&mut self, n: &Notification) -> Result<(), String> {
        notify_rust::Notification::new()
            .appname("scribe")
            .summary(&n.title)
            .body(&n.body)
            .show()
            .map(drop)
            .map_err(|e| e.to_string())
    }
}
