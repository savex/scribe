//! Linux sensor based on eBPF (planned: C programs loaded with `libbpf-rs`, plan option 7B).
//!
//! Probes: `tcp_connect` / `udp_sendmsg` kprobes and cgroup sock hooks for flow + pid,
//! a socket filter for DNS answers and TLS ClientHello payloads.
//! The programs will live in `src/bpf/*.bpf.c` (C, CO-RE, with a checked-in `vmlinux.h`); `build.rs`
//! compiles them with `clang -target bpf` and `libbpf-cargo` generates the Rust skeleton.
#![cfg(target_os = "linux")]

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
        // TODO: load and attach eBPF programs, read the ring buffer.
        Err(SensorError::Unsupported("eBPF sensor not implemented yet"))
    }

    fn stop(&mut self) {}
}
