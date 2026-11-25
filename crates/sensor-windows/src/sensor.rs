//! The ETW session (Windows): not written yet (plan 8A step 2). Until then scribed uses the pcap
//! sensor with socket-table attribution on Windows.

use std::sync::mpsc::Sender;

use scribe_core::{Observation, Sensor, SensorError};

#[derive(Default)]
pub struct EtwSensor;

impl Sensor for EtwSensor {
    fn name(&self) -> &'static str {
        "windows-etw"
    }

    fn has_process_info(&self) -> bool {
        true
    }

    fn start(&mut self, _out: Sender<Observation>) -> Result<(), SensorError> {
        Err(SensorError::Unsupported("ETW sensor not implemented yet"))
    }

    fn stop(&mut self) {}
}
