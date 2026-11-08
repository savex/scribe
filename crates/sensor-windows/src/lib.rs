//! Windows sensor based on ETW (planned: `windows` crate).
//!
//! Providers: Microsoft-Windows-Kernel-Network (flows + pid) and
//! Microsoft-Windows-DNS-Client (hostnames). A WFP callout or WinDivert may follow for blocking.
#![cfg(windows)]

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
        // TODO: open a real-time ETW session and translate events.
        Err(SensorError::Unsupported("ETW sensor not implemented yet"))
    }

    fn stop(&mut self) {}
}
