use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scribe_core::{FlowEvent, FlowKind, Protocol, Security, Sensor, SensorError};

/// Sensor that replays a fixed list of events when started.
pub struct FakeSensor {
    events: Vec<FlowEvent>,
    has_process_info: bool,
    running: bool,
}

impl FakeSensor {
    pub fn new(events: Vec<FlowEvent>) -> Self {
        Self { events, has_process_info: true, running: false }
    }

    /// Behave like the pcap fallback, which cannot attribute flows to processes.
    pub fn without_process_info(mut self) -> Self {
        self.has_process_info = false;
        self
    }

    pub fn is_running(&self) -> bool {
        self.running
    }
}

impl Sensor for FakeSensor {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn has_process_info(&self) -> bool {
        self.has_process_info
    }

    fn start(&mut self, out: Sender<FlowEvent>) -> Result<(), SensorError> {
        self.running = true;
        for event in &self.events {
            if out.send(event.clone()).is_err() {
                break; // receiver gone; the test is over
            }
        }
        Ok(())
    }

    fn stop(&mut self) {
        self.running = false;
    }
}

/// Start building a flow event to `dst` (e.g. `"198.51.100.7:8443"` or `"[2001:db8::1]:443"`).
pub fn flow(dst: &str) -> FlowBuilder {
    let dst: SocketAddr = dst.parse().expect("flow(): dst must be ip:port");
    FlowBuilder(FlowEvent {
        ts: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        pid: None,
        process_path: None,
        proto: Protocol::Tcp,
        src: SocketAddr::from(([10, 0, 0, 2], 50000)),
        dst_ip: dst.ip(),
        dst_port: dst.port(),
        hostname: None,
        url: None,
        security: Security::Unknown,
        bytes_out: 0,
        kind: FlowKind::NewFlow,
    })
}

#[derive(Debug, Clone)]
pub struct FlowBuilder(FlowEvent);

impl FlowBuilder {
    pub fn host(mut self, name: &str) -> Self {
        self.0.hostname = Some(name.into());
        self
    }

    pub fn process(mut self, pid: u32, path: &str) -> Self {
        self.0.pid = Some(pid);
        self.0.process_path = Some(path.into());
        self
    }

    pub fn at(mut self, ts: SystemTime) -> Self {
        self.0.ts = ts;
        self
    }

    pub fn after(mut self, offset: Duration) -> Self {
        self.0.ts += offset;
        self
    }

    pub fn tls(mut self) -> Self {
        self.0.security = Security::Tls;
        self
    }

    pub fn plaintext(mut self) -> Self {
        self.0.security = Security::Plaintext;
        self
    }

    pub fn udp(mut self) -> Self {
        self.0.proto = Protocol::Udp;
        self
    }

    pub fn quic(mut self) -> Self {
        self.0.proto = Protocol::Quic;
        self.0.security = Security::Quic;
        self
    }

    pub fn bytes(mut self, bytes_out: u64) -> Self {
        self.0.bytes_out = bytes_out;
        self
    }

    /// A plaintext HTTP request inside an existing flow.
    pub fn request(mut self, url: &str) -> Self {
        self.0.kind = FlowKind::Request;
        self.0.security = Security::Plaintext;
        self.0.url = Some(url.into());
        self
    }

    pub fn close(mut self) -> Self {
        self.0.kind = FlowKind::Close;
        self
    }

    pub fn build(self) -> FlowEvent {
        self.0
    }
}
