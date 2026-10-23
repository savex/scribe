use std::sync::Mutex;

use scribe_core::{Alert, AlertOutput};

/// Alert output that keeps every alert for later assertions.
#[derive(Debug, Default)]
pub struct RecordingAlertSink {
    alerts: Mutex<Vec<Alert>>,
}

impl RecordingAlertSink {
    pub fn alerts(&self) -> Vec<Alert> {
        self.alerts.lock().unwrap().clone()
    }

    pub fn count(&self) -> usize {
        self.alerts.lock().unwrap().len()
    }

    pub fn clear(&self) {
        self.alerts.lock().unwrap().clear();
    }
}

impl AlertOutput for RecordingAlertSink {
    fn name(&self) -> &str {
        "recording"
    }

    fn notify(&self, alert: &Alert) {
        self.alerts.lock().unwrap().push(alert.clone());
    }
}
