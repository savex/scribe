use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use scribe_core::{Alert, AlertOutput, Clock};
use tracing::{info, warn};

use crate::throttle::{Admit, Throttle};

/// Alerts waiting per output; more are dropped and counted.
pub const QUEUE: usize = 256;

/// Counters of one output since the dispatcher started.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutputStats {
    pub name: String,
    /// Alerts the output accepted.
    pub sent: u64,
    /// Alerts the output reported an error for.
    pub failed: u64,
    /// Alerts held back by the rate limit.
    pub suppressed: u64,
    /// Alerts dropped because the output's queue was full.
    pub dropped: u64,
    /// The output's last error, cleared by the next success.
    pub last_error: Option<String>,
}

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    failed: AtomicU64,
    suppressed: AtomicU64,
    dropped: AtomicU64,
    last_error: std::sync::Mutex<Option<String>>,
}

enum Job {
    Alert(Box<Alert>),
    Suppressed(u64),
}

struct Lane {
    name: String,
    tx: Option<SyncSender<Job>>,
    throttle: Throttle,
    counters: Arc<Counters>,
    done: Receiver<()>,
}

/// Hands alerts to every output on its own thread (see the crate docs). Decisions (rate limit,
/// queue full) are made on the caller's thread with its [`Clock`], so tests can drive them with
/// `FakeClock`.
pub struct Dispatcher {
    lanes: Vec<Lane>,
    clock: Arc<dyn Clock>,
}

impl Dispatcher {
    /// One lane per output, each limited to `max_per_minute` alerts (`0` = unlimited).
    pub fn new(
        outputs: Vec<Arc<dyn AlertOutput>>,
        max_per_minute: u32,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let lanes = outputs
            .into_iter()
            .map(|output| Lane::spawn(output, max_per_minute))
            .collect();
        Self { lanes, clock }
    }

    /// No outputs at all.
    pub fn empty(clock: Arc<dyn Clock>) -> Self {
        Self::new(Vec::new(), 0, clock)
    }

    pub fn names(&self) -> Vec<&str> {
        self.lanes.iter().map(|l| l.name.as_str()).collect()
    }

    /// Queue `alert` for every output its rate limit lets through.
    pub fn send(&mut self, alert: &Alert) {
        let now = self.clock.now();
        for lane in &mut self.lanes {
            lane.roll(now);
            match lane.throttle.admit(now) {
                Admit::Send => lane.push(Job::Alert(Box::new(alert.clone()))),
                Admit::Suppress => {
                    lane.counters.suppressed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Report rate-limit windows that have ended; call about once a second.
    pub fn tick(&mut self) {
        let now = self.clock.now();
        for lane in &mut self.lanes {
            lane.roll(now);
        }
    }

    pub fn stats(&self) -> Vec<OutputStats> {
        self.lanes
            .iter()
            .map(|l| OutputStats {
                name: l.name.clone(),
                sent: l.counters.sent.load(Ordering::Relaxed),
                failed: l.counters.failed.load(Ordering::Relaxed),
                suppressed: l.counters.suppressed.load(Ordering::Relaxed),
                dropped: l.counters.dropped.load(Ordering::Relaxed),
                last_error: l.counters.last_error.lock().unwrap().clone(),
            })
            .collect()
    }

    /// Stop taking alerts and give the outputs up to `grace` in all to finish their queues; an
    /// output still busy after that (a webhook waiting for its timeout) is left to finish on its
    /// own. Returns the names of outputs that did not finish in time.
    pub fn close(mut self, grace: Duration) -> Vec<String> {
        for lane in &mut self.lanes {
            lane.tx = None;
        }
        let per_lane = grace / u32::try_from(self.lanes.len().max(1)).unwrap_or(u32::MAX);
        let mut late = Vec::new();
        for lane in &self.lanes {
            match lane.done.recv_timeout(per_lane) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {}
                Err(RecvTimeoutError::Timeout) => late.push(lane.name.clone()),
            }
        }
        late
    }
}

impl Lane {
    fn spawn(output: Arc<dyn AlertOutput>, max_per_minute: u32) -> Self {
        let name = output.name().to_owned();
        let (tx, rx) = mpsc::sync_channel::<Job>(QUEUE);
        let (done_tx, done) = mpsc::channel();
        let counters = Arc::new(Counters::default());
        let shared = counters.clone();
        let thread_name = format!("scribe-alerts-{name}");
        let spawned = std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                run(output.as_ref(), rx, &shared);
                let _ = done_tx.send(());
            });
        let tx = match spawned {
            Ok(_) => Some(tx),
            Err(e) => {
                warn!(output = %name, "cannot start the alert output thread: {e}");
                None
            }
        };
        Self {
            name,
            tx,
            throttle: Throttle::new(max_per_minute),
            counters,
            done,
        }
    }

    fn roll(&mut self, now: std::time::SystemTime) {
        if let Some(held) = self.throttle.roll(now) {
            info!(
                output = %self.name,
                suppressed = held,
                "{held} alerts were not sent to {} in the last minute (alerts.max_per_minute = {})",
                self.name,
                self.throttle.max_per_minute()
            );
            self.push(Job::Suppressed(held));
        }
    }

    fn push(&self, job: Job) {
        let Some(tx) = &self.tx else {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match tx.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                let dropped = self.counters.dropped.fetch_add(1, Ordering::Relaxed);
                if dropped == 0 {
                    warn!(
                        output = %self.name,
                        "alert output {} is behind; alerts for it are dropped while its queue is full",
                        self.name
                    );
                }
            }
        }
    }
}

/// The output thread: deliver jobs in order until the dispatcher closes the queue. Failures are
/// logged once until the output works again.
fn run(output: &dyn AlertOutput, rx: Receiver<Job>, counters: &Counters) {
    let mut failing = false;
    for job in rx {
        let result = match &job {
            Job::Alert(alert) => output.notify(alert),
            Job::Suppressed(n) => output.suppressed(*n),
        };
        match result {
            Ok(()) => {
                if matches!(job, Job::Alert(_)) {
                    counters.sent.fetch_add(1, Ordering::Relaxed);
                }
                if failing {
                    failing = false;
                    info!(output = output.name(), "alert output works again");
                }
                *counters.last_error.lock().unwrap() = None;
            }
            Err(e) => {
                if matches!(job, Job::Alert(_)) {
                    counters.failed.fetch_add(1, Ordering::Relaxed);
                }
                if !failing {
                    failing = true;
                    warn!(output = output.name(), "alert output failed: {e}");
                }
                *counters.last_error.lock().unwrap() = Some(e);
            }
        }
    }
}
