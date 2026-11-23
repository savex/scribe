//! Fallback sensor on every OS: libpcap (Linux, macOS) or Npcap (Windows), loaded at run time
//! ([`ffi`]). It sees packets, not processes, so flows carry no pid or path.
//!
//! [`decode`] turns frames into TCP / UDP packets, [`flows`] turns packets into observations, and
//! [`file`] reads pcap files so captures and fixtures replay through the same code.

pub mod decode;
pub mod ffi;
pub mod file;
pub mod flows;

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use scribe_core::{Clock, Observation, Sensor, SensorError, SystemClock};

use crate::ffi::{Device, Lib, Next, OpenError};
use crate::flows::{FlowTracker, TrackerOptions};

/// Pick the device to capture on and the local addresses that make a flow outgoing.
///
/// `wanted` names a device; without it: Linux's `any` (every interface) when present, else the
/// first device that is up, not loopback and has an address. Local addresses are those of every
/// device, so flows from any interface of this machine count as outgoing.
pub fn choose_device(
    devices: &[Device],
    wanted: Option<&str>,
) -> Result<(String, Vec<IpAddr>), String> {
    let local: Vec<IpAddr> = devices
        .iter()
        .flat_map(|d| d.addresses.iter().copied())
        .collect();
    let name = match wanted.filter(|w| !w.is_empty()) {
        Some(w) => devices
            .iter()
            .find(|d| d.name == w)
            .map(|d| d.name.clone())
            .ok_or_else(|| {
                let names: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
                format!("no capture device \"{w}\" (devices: {})", names.join(", "))
            })?,
        None => devices
            .iter()
            .find(|d| d.name == "any")
            .or_else(|| {
                devices
                    .iter()
                    .find(|d| d.is_up() && !d.is_loopback() && !d.addresses.is_empty())
            })
            .map(|d| d.name.clone())
            .ok_or_else(|| "no capture device is up with an address".to_owned())?,
    };
    Ok((name, local))
}

struct Running {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

pub struct PcapSensor {
    /// Capture device; `None` or empty = automatic ([`choose_device`]).
    pub interface: Option<String>,
    payload: bool,
    clock: Arc<dyn Clock>,
    running: Option<Running>,
}

impl PcapSensor {
    pub fn new(interface: Option<String>) -> Self {
        Self {
            interface,
            payload: true,
            clock: Arc::new(SystemClock),
            running: None,
        }
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
}

impl Sensor for PcapSensor {
    fn name(&self) -> &'static str {
        "pcap"
    }

    fn has_process_info(&self) -> bool {
        false
    }

    fn set_payload(&mut self, needed: bool) {
        self.payload = needed;
    }

    fn start(&mut self, out: Sender<Observation>) -> Result<(), SensorError> {
        if self.running.is_some() {
            return Ok(());
        }
        let lib = Lib::load().map_err(|e| SensorError::Io(std::io::Error::other(e)))?;
        let devices = lib
            .devices()
            .map_err(|e| SensorError::Io(std::io::Error::other(e)))?;
        let (device, local) = choose_device(&devices, self.interface.as_deref())
            .map_err(|e| SensorError::Io(std::io::Error::other(e)))?;
        let mut handle = lib.open(&device).map_err(|e| match e {
            OpenError::Permission(m) => SensorError::Permission(format!("{device}: {m}")),
            OpenError::Other(m) => SensorError::Io(std::io::Error::other(format!("{device}: {m}"))),
        })?;
        let linktype = handle.linktype();
        if !decode::supported(linktype) {
            return Err(SensorError::Io(std::io::Error::other(format!(
                "{device}: link type {linktype} is not supported"
            ))));
        }
        let opts = TrackerOptions {
            payload: self.payload,
            local,
            ..TrackerOptions::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let clock = self.clock.clone();
        let thread = std::thread::Builder::new()
            .name(format!("scribe-pcap-{device}"))
            .spawn(move || {
                let mut tracker = FlowTracker::new(opts);
                let mut last_tick = clock.now();
                let send = |obs: Vec<Observation>| obs.into_iter().all(|o| out.send(o).is_ok());
                while !stopping.load(Ordering::Relaxed) {
                    let batch = match handle.read() {
                        Next::Packet { ts, data } => match decode::decode(linktype, data, ts) {
                            Some(p) => tracker.push(&p),
                            None => Vec::new(),
                        },
                        Next::Timeout => {
                            // Nothing waiting: a short pause keeps the loop cheap and `stop` quick.
                            std::thread::sleep(Duration::from_millis(20));
                            Vec::new()
                        }
                        Next::Error(e) => {
                            tracing::warn!(device = %device, "packet capture stopped: {e}");
                            break;
                        }
                    };
                    if !send(batch) {
                        break; // the daemon is gone
                    }
                    let now = clock.now();
                    if now.duration_since(last_tick).unwrap_or(Duration::ZERO)
                        >= Duration::from_millis(250)
                    {
                        last_tick = now;
                        if !send(tracker.tick(now)) {
                            break;
                        }
                    }
                }
                send(tracker.flush());
            })
            .map_err(SensorError::Io)?;
        self.running = Some(Running { stop, thread });
        Ok(())
    }

    /// Stops capture and waits (about 20 ms) for the open flows to be closed.
    fn stop(&mut self) {
        if let Some(r) = self.running.take() {
            r.stop.store(true, Ordering::Relaxed);
            let _ = r.thread.join();
        }
    }
}

impl Drop for PcapSensor {
    fn drop(&mut self) {
        self.stop();
    }
}
