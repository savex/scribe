use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scribe_core::{
    FlowEvent, FlowKind, Notes, Observation, Protocol, Security, Sensor, SensorError,
};

use crate::packets::http;

/// Sensor that replays a fixed list of observations each time it is started.
pub struct FakeSensor {
    observations: Vec<Observation>,
    has_process_info: bool,
    running: bool,
    starts: usize,
}

impl FakeSensor {
    /// Events without payload bytes.
    pub fn new(events: Vec<FlowEvent>) -> Self {
        Self::from_observations(events.into_iter().map(Observation::new).collect())
    }

    pub fn from_observations(observations: Vec<Observation>) -> Self {
        Self {
            observations,
            has_process_info: true,
            running: false,
            starts: 0,
        }
    }

    /// Behave like the pcap fallback, which cannot attribute flows to processes.
    pub fn without_process_info(mut self) -> Self {
        self.has_process_info = false;
        self
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    /// How often `start` was called (sensors must start again after `stop`).
    pub fn starts(&self) -> usize {
        self.starts
    }
}

impl Sensor for FakeSensor {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn has_process_info(&self) -> bool {
        self.has_process_info
    }

    fn start(&mut self, out: Sender<Observation>) -> Result<(), SensorError> {
        self.running = true;
        self.starts += 1;
        for observation in &self.observations {
            if out.send(observation.clone()).is_err() {
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
    FlowBuilder {
        event: FlowEvent {
            ts: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            pid: None,
            process_path: None,
            proto: Protocol::Tcp,
            src: SocketAddr::from(([10, 0, 0, 2], 50000)),
            dst_ip: dst.ip(),
            dst_port: dst.port(),
            hostname: None,
            notes: Notes::new(),
            security: Security::Unknown,
            bytes_out: 0,
            kind: FlowKind::NewFlow,
        },
        head: None,
    }
}

#[derive(Debug, Clone)]
pub struct FlowBuilder {
    event: FlowEvent,
    head: Option<Vec<u8>>,
}

impl FlowBuilder {
    pub fn host(mut self, name: &str) -> Self {
        self.event.hostname = Some(name.into());
        self
    }

    pub fn process(mut self, pid: u32, path: &str) -> Self {
        self.event.pid = Some(pid);
        self.event.process_path = Some(path.into());
        self
    }

    pub fn at(mut self, ts: SystemTime) -> Self {
        self.event.ts = ts;
        self
    }

    pub fn after(mut self, offset: Duration) -> Self {
        self.event.ts += offset;
        self
    }

    pub fn tls(mut self) -> Self {
        self.event.security = Security::Tls;
        self
    }

    pub fn plaintext(mut self) -> Self {
        self.event.security = Security::Plaintext;
        self
    }

    pub fn udp(mut self) -> Self {
        self.event.proto = Protocol::Udp;
        self
    }

    pub fn quic(mut self) -> Self {
        self.event.proto = Protocol::Quic;
        self.event.security = Security::Quic;
        self
    }

    pub fn bytes(mut self, bytes_out: u64) -> Self {
        self.event.bytes_out = bytes_out;
        self
    }

    /// Client bytes seen on an existing flow.
    pub fn payload(mut self, bytes: &[u8]) -> Self {
        self.event.kind = FlowKind::Payload;
        self.head = Some(bytes.to_vec());
        self
    }

    /// A plaintext HTTP GET for `url` (`http://host/path?query`) on an existing flow: the
    /// request bytes a sensor would pass on. Sets the host name from the URL.
    pub fn http_get(mut self, url: &str) -> Self {
        let rest = url
            .strip_prefix("http://")
            .expect("http_get(): url must start with http://");
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        self.event.security = Security::Plaintext;
        self.event.hostname = Some(host.into());
        self.payload(&http::get_request(host, path))
    }

    /// Attach a module note, as the module would.
    pub fn note(mut self, module: &str, value: serde_json::Value) -> Self {
        self.event.notes.insert(module, value);
        self
    }

    pub fn close(mut self) -> Self {
        self.event.kind = FlowKind::Close;
        self
    }

    pub fn build(self) -> FlowEvent {
        self.event
    }

    /// The event with its payload bytes, as a sensor reports it.
    pub fn observe(self) -> Observation {
        match &self.head {
            Some(bytes) => Observation::new(self.event.clone()).with_head(bytes),
            None => Observation::new(self.event),
        }
    }
}
