use std::sync::mpsc::Sender;

use scribe_core::{Observation, Sensor, SensorError};

#[derive(Default)]
pub struct EbpfSensor;

impl Sensor for EbpfSensor {
    fn name(&self) -> &'static str {
        "linux-ebpf"
    }

    fn has_process_info(&self) -> bool {
        true
    }

    fn start(&mut self, _out: Sender<Observation>) -> Result<(), SensorError> {
        // TODO(7B step 3): load and attach the eBPF programs, read the ring buffer and packets.
        Err(SensorError::Unsupported("eBPF sensor not implemented yet"))
    }

    fn stop(&mut self) {}
}
