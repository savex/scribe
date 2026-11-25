use std::sync::mpsc::Sender;
use std::time::Duration;

use crate::Observation;

/// A platform capture backend. Implementations push observations (normalized events plus the
/// first client bytes) into `out`. `start` may be called again after `stop`.
pub trait Sensor: Send {
    fn name(&self) -> &'static str;
    /// Whether events carry pid / process path.
    fn has_process_info(&self) -> bool;
    fn start(&mut self, out: Sender<Observation>) -> Result<(), SensorError>;
    fn stop(&mut self);
    /// Whether an enabled module needs client bytes past the first request (set before `start`).
    /// Sensors that always send what they have can ignore it.
    fn set_payload(&mut self, _needed: bool) {}
    /// How many new flows got a process: the socket-table lookup (with its table reads) and
    /// native sensors that join kernel records with packets.
    fn attribution(&self) -> Option<AttributionStats> {
        None
    }
}

/// Process attribution: new flows that got a process or not, and for the socket-table lookup
/// (plan option P) how long reading the table takes (all zero for native sensors).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttributionStats {
    /// New flows that got their process from the table.
    pub attributed: u64,
    /// New flows whose socket was not in the table (already closed, or not readable).
    pub missed: u64,
    /// Reads of the whole table.
    pub scans: u64,
    /// Reads that took longer than the scan budget; each one spaces the next reads out.
    pub slow_scans: u64,
    pub last_scan: Duration,
    pub max_scan: Duration,
}

impl AttributionStats {
    /// Share of new flows with a process, `None` before the first one.
    pub fn hit_rate(&self) -> Option<f64> {
        let total = self.attributed + self.missed;
        (total > 0).then(|| self.attributed as f64 / total as f64)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SensorError {
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    #[error("permission denied: {0}")]
    Permission(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
