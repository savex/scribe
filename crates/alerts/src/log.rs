use std::net::SocketAddr;

use scribe_core::{Alert, AlertOutput};
use tracing::warn;

/// Writes each alert as a `scribe::alert` warning in scribed's own log (file, system log or both,
/// as `[log] output` says), with the reason, host, destination, process, score and the module
/// notes (e.g. the URL, already redacted by `[modules.url] query`).
#[derive(Debug, Default, Clone, Copy)]
pub struct LogOutput;

/// The message of an alert's log line: `alert <reason>: <host> (<dst>)`.
pub fn alert_line(alert: &Alert) -> String {
    let dst = SocketAddr::new(alert.dst_ip, alert.dst_port);
    match &alert.host {
        Some(host) => format!("alert {}: {host} ({dst})", alert.reason),
        None => format!("alert {}: {dst}", alert.reason),
    }
}

fn notes(alert: &Alert) -> String {
    alert
        .notes
        .iter()
        .map(|(k, v)| match v.as_str() {
            Some(s) => format!("{k}={s}"),
            None => format!("{k}={v}"),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl AlertOutput for LogOutput {
    fn name(&self) -> &str {
        "log"
    }

    fn notify(&self, alert: &Alert) -> Result<(), String> {
        warn!(
            target: "scribe::alert",
            reason = %alert.reason,
            host = alert.host.as_deref().unwrap_or("-"),
            dst = %SocketAddr::new(alert.dst_ip, alert.dst_port),
            process = alert.process_path.as_deref().unwrap_or("-"),
            score = alert.score,
            notes = %notes(alert),
            "{}",
            alert_line(alert)
        );
        Ok(())
    }

    fn suppressed(&self, count: u64) -> Result<(), String> {
        warn!(
            target: "scribe::alert",
            suppressed = count,
            "{count} more alerts in the last minute were not logged one by one (alerts.max_per_minute); \
             `scribe alerts` lists them all"
        );
        Ok(())
    }
}
