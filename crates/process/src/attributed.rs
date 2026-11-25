use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};

use scribe_core::{AttributionStats, FlowKind, Observation, Protocol, Sensor, SensorError};

use crate::table::{Resolver, Transport};

#[derive(Default)]
struct Counters {
    attributed: AtomicU64,
    missed: AtomicU64,
}

/// A sensor whose new flows and later requests get their process from the socket table when the
/// sensor itself doesn't know it. The lookup runs on a thread of its own between the sensor and
/// scribed, so capture is never slowed by it.
pub struct Attributed {
    inner: Box<dyn Sensor>,
    resolver: Arc<Mutex<Resolver>>,
    counters: Arc<Counters>,
}

impl Attributed {
    pub fn new(inner: Box<dyn Sensor>, resolver: Resolver) -> Self {
        Self {
            inner,
            resolver: Arc::new(Mutex::new(resolver)),
            counters: Arc::new(Counters::default()),
        }
    }

    /// New flows with and without a process, and the table reads behind them.
    pub fn stats(&self) -> AttributionStats {
        let scans = self
            .resolver
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .scan_stats();
        AttributionStats {
            attributed: self.counters.attributed.load(Ordering::Relaxed),
            missed: self.counters.missed.load(Ordering::Relaxed),
            scans: scans.scans,
            slow_scans: scans.slow,
            last_scan: scans.last,
            max_scan: scans.max,
        }
    }
}

fn attribute(obs: &mut Observation, resolver: &Mutex<Resolver>, counters: &Counters) {
    let e = &mut obs.event;
    if e.pid.is_some() || !matches!(e.kind, FlowKind::NewFlow | FlowKind::Payload) {
        return;
    }
    let transport = match e.proto {
        Protocol::Tcp => Transport::Tcp,
        Protocol::Udp | Protocol::Quic => Transport::Udp,
    };
    let remote = std::net::SocketAddr::new(e.dst_ip, e.dst_port);
    let owner = resolver
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .lookup(transport, e.src, remote);
    let counter = match owner {
        Some(owner) => {
            e.pid = Some(owner.pid);
            e.process_path = owner.path;
            &counters.attributed
        }
        None => &counters.missed,
    };
    if e.kind == FlowKind::NewFlow {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

impl Sensor for Attributed {
    fn name(&self) -> &'static str {
        match self.inner.name() {
            "pcap" => "pcap+sockets",
            other => other,
        }
    }

    fn has_process_info(&self) -> bool {
        true
    }

    fn set_payload(&mut self, needed: bool) {
        self.inner.set_payload(needed);
    }

    fn attribution(&self) -> Option<AttributionStats> {
        Some(self.stats())
    }

    fn start(&mut self, out: Sender<Observation>) -> Result<(), SensorError> {
        let (tx, rx) = mpsc::channel::<Observation>();
        self.inner.start(tx)?;
        let resolver = self.resolver.clone();
        let counters = self.counters.clone();
        // Ends when the inner sensor drops its sender (stop) or scribed stops listening.
        std::thread::Builder::new()
            .name("scribe-process-attribution".into())
            .spawn(move || {
                for mut obs in rx {
                    attribute(&mut obs, &resolver, &counters);
                    if out.send(obs).is_err() {
                        break;
                    }
                }
            })
            .map_err(SensorError::Io)?;
        Ok(())
    }

    fn stop(&mut self) {
        self.inner.stop();
        let s = self.stats();
        tracing::info!(
            attributed = s.attributed,
            missed = s.missed,
            scans = s.scans,
            slow_scans = s.slow_scans,
            max_scan_ms = s.max_scan.as_millis() as u64,
            "process attribution from the socket table"
        );
    }
}
