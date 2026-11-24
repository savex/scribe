use std::net::IpAddr;
use std::time::SystemTime;

use crate::Notes;

/// An alert raised by the policy engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub ts: SystemTime,
    pub host: Option<String>,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub process_path: Option<String>,
    pub score: u32,
    pub reason: String,
    /// The flow's module notes (e.g. the URL), so an alert shows what was requested.
    pub notes: Notes,
}

/// Destination for alerts: log, webhook (`scribe-alerts`); OS notifications come from the
/// `scribe notify` agent in the user's session. Each output runs on its own thread, so a slow one
/// never holds up the pipeline or the other outputs.
pub trait AlertOutput: Send + Sync {
    fn name(&self) -> &str;
    /// Deliver one alert; an `Err` is counted and logged by the dispatcher.
    fn notify(&self, alert: &Alert) -> Result<(), String>;
    /// `count` alerts were held back by the rate limit during the window that just ended.
    fn suppressed(&self, count: u64) -> Result<(), String> {
        let _ = count;
        Ok(())
    }
}
