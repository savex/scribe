//! Fallback sensor that works on every OS via libpcap (Linux, macOS) or Npcap (Windows).
//! It sees packets but cannot attribute them to processes.

use std::sync::mpsc::Sender;

use scribe_core::{FlowEvent, Sensor, SensorError};

pub struct PcapSensor {
    pub interface: Option<String>,
}

impl Sensor for PcapSensor {
    fn name(&self) -> &'static str {
        "pcap"
    }

    fn has_process_info(&self) -> bool {
        false
    }

    fn start(&mut self, _out: Sender<FlowEvent>) -> Result<(), SensorError> {
        // TODO: add the `pcap` crate, capture outbound SYN / UDP / DNS / ClientHello packets.
        Err(SensorError::Unsupported("pcap sensor not implemented yet"))
    }

    fn stop(&mut self) {}
}
