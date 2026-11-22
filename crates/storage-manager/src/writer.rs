//! One writer task per event sink: batches events by size and time, writes them, and applies
//! retention for sinks that can't do it themselves (specs 7.1, FR-17, FR-19).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scribe_core::Clock;
use scribe_storage_api::{EventSink, StoredEvent};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep_until, Instant};

use crate::SinkConfig;

pub(crate) enum Command {
    Events(Vec<StoredEvent>),
    /// Write everything queued so far, then answer.
    Flush(oneshot::Sender<()>),
}

/// Live counters for one sink (`scribe daemon status`).
#[derive(Debug, Default)]
pub struct SinkCounters {
    /// Events accepted into the queue.
    pub queued: AtomicU64,
    /// Events written to the sink.
    pub written: AtomicU64,
    pub batches: AtomicU64,
    pub write_errors: AtomicU64,
    /// Events dropped because the queue was full.
    pub dropped_queue_full: AtomicU64,
    /// Events dropped because a write failed (until the spool exists).
    pub dropped_write_failed: AtomicU64,
    /// Records removed by retention.
    pub retention_deleted: AtomicU64,
    pub last_error: Mutex<Option<String>>,
}

/// A snapshot of [`SinkCounters`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SinkStatus {
    pub name: String,
    pub queued: u64,
    pub written: u64,
    pub batches: u64,
    pub write_errors: u64,
    pub dropped_queue_full: u64,
    pub dropped_write_failed: u64,
    pub retention_deleted: u64,
    pub last_error: Option<String>,
}

impl SinkCounters {
    pub(crate) fn snapshot(&self, name: &str) -> SinkStatus {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        SinkStatus {
            name: name.to_owned(),
            queued: get(&self.queued),
            written: get(&self.written),
            batches: get(&self.batches),
            write_errors: get(&self.write_errors),
            dropped_queue_full: get(&self.dropped_queue_full),
            dropped_write_failed: get(&self.dropped_write_failed),
            retention_deleted: get(&self.retention_deleted),
            last_error: self.last_error.lock().unwrap().clone(),
        }
    }

    fn add(c: &AtomicU64, n: usize) {
        c.fetch_add(n as u64, Ordering::Relaxed);
    }
}

pub(crate) struct Writer {
    pub(crate) config: SinkConfig,
    pub(crate) sink: Arc<dyn EventSink>,
    pub(crate) counters: Arc<SinkCounters>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) retention_every: Duration,
}

impl Writer {
    /// Largest batch: the sink's own limit or the configured size, whichever is smaller.
    fn batch_limit(&self) -> usize {
        let caps = self.sink.capabilities().max_batch.max(1);
        (self.config.batch_max_events as usize).clamp(1, caps)
    }

    pub(crate) async fn run(self, mut rx: mpsc::Receiver<Command>) {
        let limit = self.batch_limit();
        let wait = self.config.batch_max_wait;
        let retention = self
            .config
            .retention
            .filter(|_| !self.sink.capabilities().native_retention);
        let mut next_retention = Instant::now();
        let mut pending: Vec<StoredEvent> = Vec::new();
        let mut deadline: Option<Instant> = None;

        loop {
            let timer = async {
                match deadline {
                    Some(at) => sleep_until(at).await,
                    None => std::future::pending().await,
                }
            };
            let retention_timer = async {
                match retention {
                    Some(_) => sleep_until(next_retention).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                cmd = rx.recv() => match cmd {
                    Some(Command::Events(events)) => {
                        if pending.is_empty() {
                            deadline = Some(Instant::now() + wait);
                        }
                        pending.extend(events);
                        while pending.len() >= limit {
                            let rest = pending.split_off(limit);
                            self.write(std::mem::replace(&mut pending, rest)).await;
                        }
                        if pending.is_empty() {
                            deadline = None;
                        }
                    }
                    Some(Command::Flush(done)) => {
                        self.write_all(&mut pending, limit).await;
                        deadline = None;
                        let _ = done.send(());
                    }
                    None => {
                        self.write_all(&mut pending, limit).await;
                        match self.sink.flush().await {
                            Ok(()) | Err(scribe_storage_api::StorageError::NotImplemented(_)) => {}
                            Err(e) => tracing::warn!(sink = self.config.name, "flush failed: {e}"),
                        }
                        break;
                    }
                },
                _ = timer => {
                    self.write_all(&mut pending, limit).await;
                    deadline = None;
                }
                _ = retention_timer => {
                    if let Some(keep) = retention {
                        self.apply_retention(keep).await;
                    }
                    next_retention = Instant::now() + self.retention_every;
                }
            }
        }
    }

    async fn write_all(&self, pending: &mut Vec<StoredEvent>, limit: usize) {
        while !pending.is_empty() {
            let rest = pending.split_off(pending.len().min(limit));
            self.write(std::mem::replace(pending, rest)).await;
        }
    }

    async fn write(&self, batch: Vec<StoredEvent>) {
        if batch.is_empty() {
            return;
        }
        match self.sink.write_batch(&batch).await {
            Ok(()) => {
                SinkCounters::add(&self.counters.written, batch.len());
                SinkCounters::add(&self.counters.batches, 1);
            }
            Err(e) => {
                SinkCounters::add(&self.counters.write_errors, 1);
                SinkCounters::add(&self.counters.dropped_write_failed, batch.len());
                *self.counters.last_error.lock().unwrap() = Some(e.to_string());
                tracing::warn!(sink = self.config.name, "write failed: {e}");
            }
        }
    }

    async fn apply_retention(&self, keep: Duration) {
        let cutoff = self.clock.now() - keep;
        match self.sink.delete_before(cutoff).await {
            Ok(n) => SinkCounters::add(&self.counters.retention_deleted, n as usize),
            Err(e) => tracing::warn!(sink = self.config.name, "retention failed: {e}"),
        }
    }
}
