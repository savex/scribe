use std::sync::Mutex;

use scribe_core::{Alert, AlertOutput};

/// Alert output that keeps every alert (and every rate-limit summary) for later assertions.
#[derive(Debug, Default)]
pub struct RecordingAlertSink {
    alerts: Mutex<Vec<Alert>>,
    suppressed: Mutex<Vec<u64>>,
}

impl RecordingAlertSink {
    pub fn alerts(&self) -> Vec<Alert> {
        self.alerts.lock().unwrap().clone()
    }

    pub fn count(&self) -> usize {
        self.alerts.lock().unwrap().len()
    }

    /// The counts passed to [`AlertOutput::suppressed`], in order.
    pub fn suppressed_counts(&self) -> Vec<u64> {
        self.suppressed.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.alerts.lock().unwrap().clear();
        self.suppressed.lock().unwrap().clear();
    }
}

impl AlertOutput for RecordingAlertSink {
    fn name(&self) -> &str {
        "recording"
    }

    fn notify(&self, alert: &Alert) -> Result<(), String> {
        self.alerts.lock().unwrap().push(alert.clone());
        Ok(())
    }

    fn suppressed(&self, count: u64) -> Result<(), String> {
        self.suppressed.lock().unwrap().push(count);
        Ok(())
    }
}
