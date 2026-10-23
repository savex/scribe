//! Linux sensor based on eBPF (planned: `aya`).
//!
//! Probes: `tcp_connect` / `udp_sendmsg` kprobes and cgroup sock hooks for flow + pid,
//! a socket filter for DNS answers and TLS ClientHello payloads.
//! The eBPF programs will live in a separate `sensor-linux-ebpf` crate built for the bpf target.
#![cfg(target_os = "linux")]

use std::sync::mpsc::Sender;

use scribe_core::{FlowEvent, Sensor, SensorError};

#[derive(Default)]
pub struct EbpfSensor;

impl Sensor for EbpfSensor {
    fn name(&self) -> &'static str {
        "linux-ebpf"
    }

    fn has_process_info(&self) -> bool {
        true
    }

    fn start(&mut self, _out: Sender<FlowEvent>) -> Result<(), SensorError> {
        // TODO: load and attach eBPF programs, read the ring buffer.
        Err(SensorError::Unsupported("eBPF sensor not implemented yet"))
    }

    fn stop(&mut self) {}
}
