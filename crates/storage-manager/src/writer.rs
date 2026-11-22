//! One writer task per event sink: batches events by size and time, writes them, and applies
//! retention for sinks that can't do it themselves (specs 7.1, FR-17, FR-19).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scribe_core::Clock;
use scribe_storage_api::{EventSink, StoredEvent};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep_until, Instant};

use crate::spool::Spool;
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
    /// Events dropped because a write failed and there was no spool to keep them.
    pub dropped_write_failed: AtomicU64,
    /// Events moved to the spool while the sink was down.
    pub spooled: AtomicU64,
    /// Events written to the sink from the spool.
    pub replayed: AtomicU64,
    /// Spooled events dropped at the spool's size or free-disk limit.
    pub spool_dropped: AtomicU64,
    /// Spool lines that could not be read back.
    pub spool_unreadable: AtomicU64,
    /// Events waiting in the spool now.
    pub spool_events: AtomicU64,
    pub spool_bytes: AtomicU64,
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
    pub spooled: u64,
    pub replayed: u64,
    pub spool_dropped: u64,
    pub spool_unreadable: u64,
    pub spool_events: u64,
    pub spool_bytes: u64,
    pub retention_deleted: u64,
    pub last_error: Option<String>,
}

impl SinkStatus {
    /// Writing directly (nothing waiting in the spool).
    pub fn healthy(&self) -> bool {
        self.spool_events == 0
    }
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
            spooled: get(&self.spooled),
            replayed: get(&self.replayed),
            spool_dropped: get(&self.spool_dropped),
            spool_unreadable: get(&self.spool_unreadable),
            spool_events: get(&self.spool_events),
            spool_bytes: get(&self.spool_bytes),
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
    pub(crate) spool: Option<Spool>,
    pub(crate) retry_min: Duration,
    pub(crate) retry_max: Duration,
}

impl Writer {
    /// Largest batch: the sink's own limit or the configured size, whichever is smaller.
    fn batch_limit(&self) -> usize {
        let caps = self.sink.capabilities().max_batch.max(1);
        (self.config.batch_max_events as usize).clamp(1, caps)
    }

    pub(crate) async fn run(mut self, mut rx: mpsc::Receiver<Command>) {
        let limit = self.batch_limit();
        let wait = self.config.batch_max_wait;
        let retention = self
            .config
            .retention
            .filter(|_| !self.sink.capabilities().native_retention);
        let mut next_retention = Instant::now();
        let mut pending: Vec<StoredEvent> = Vec::new();
        let mut deadline: Option<Instant> = None;
        let mut backoff = self.retry_min;
        // A spool left by an earlier run is replayed first.
        let mut retry_at: Option<Instant> = self
            .spool
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|_| Instant::now());
        self.update_gauges();

        loop {
            let timer = async {
                match deadline {
                    Some(at) => sleep_until(at).await,
                    None => std::future::pending().await,
                }
            };
            let retry_timer = async {
                match retry_at {
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
                            let batch = std::mem::replace(&mut pending, rest);
                            self.deliver(batch, &mut retry_at, backoff).await;
                        }
                        if pending.is_empty() {
                            deadline = None;
                        }
                    }
                    Some(Command::Flush(done)) => {
                        self.write_all(&mut pending, limit, &mut retry_at, backoff).await;
                        if retry_at.is_some() {
                            self.retry(limit, &mut retry_at, &mut backoff).await;
                        }
                        deadline = None;
                        let _ = done.send(());
                    }
                    None => {
                        self.write_all(&mut pending, limit, &mut retry_at, backoff).await;
                        if retry_at.is_some() {
                            self.retry(limit, &mut retry_at, &mut backoff).await;
                        }
                        match self.sink.flush().await {
                            Ok(()) | Err(scribe_storage_api::StorageError::NotImplemented(_)) => {}
                            Err(e) => tracing::warn!(sink = self.config.name, "flush failed: {e}"),
                        }
                        break;
                    }
                },
                _ = timer => {
                    self.write_all(&mut pending, limit, &mut retry_at, backoff).await;
                    deadline = None;
                }
                _ = retry_timer => {
                    self.retry(limit, &mut retry_at, &mut backoff).await;
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

    async fn write_all(
        &mut self,
        pending: &mut Vec<StoredEvent>,
        limit: usize,
        retry_at: &mut Option<Instant>,
        backoff: Duration,
    ) {
        while !pending.is_empty() {
            let rest = pending.split_off(pending.len().min(limit));
            let batch = std::mem::replace(pending, rest);
            self.deliver(batch, retry_at, backoff).await;
        }
    }

    /// Write a batch, or spool it: while anything waits in the spool, new batches queue behind it
    /// so the sink sees events in order.
    async fn deliver(
        &mut self,
        batch: Vec<StoredEvent>,
        retry_at: &mut Option<Instant>,
        backoff: Duration,
    ) {
        if batch.is_empty() {
            return;
        }
        if retry_at.is_none() && self.write(&batch).await {
            return;
        }
        self.spool_batch(&batch);
        if retry_at.is_none() {
            *retry_at = Some(Instant::now() + backoff);
        }
    }

    /// Write one batch; `false` (and counted) on failure.
    async fn write(&self, batch: &[StoredEvent]) -> bool {
        match self.sink.write_batch(batch).await {
            Ok(()) => {
                SinkCounters::add(&self.counters.written, batch.len());
                SinkCounters::add(&self.counters.batches, 1);
                true
            }
            Err(e) => {
                SinkCounters::add(&self.counters.write_errors, 1);
                *self.counters.last_error.lock().unwrap() = Some(e.to_string());
                tracing::warn!(sink = self.config.name, "write failed: {e}");
                false
            }
        }
    }

    fn spool_batch(&mut self, batch: &[StoredEvent]) {
        let Some(spool) = self.spool.as_mut() else {
            SinkCounters::add(&self.counters.dropped_write_failed, batch.len());
            return;
        };
        match spool.append(batch) {
            Ok(done) => {
                SinkCounters::add(&self.counters.spooled, done.stored as usize);
                SinkCounters::add(&self.counters.spool_dropped, done.dropped as usize);
            }
            Err(e) => {
                SinkCounters::add(&self.counters.dropped_write_failed, batch.len());
                tracing::warn!(sink = self.config.name, "cannot spool: {e}");
            }
        }
        self.update_gauges();
    }

    /// Replay the spool, oldest first. On success clear `retry_at`; on failure back off.
    async fn retry(
        &mut self,
        limit: usize,
        retry_at: &mut Option<Instant>,
        backoff: &mut Duration,
    ) {
        let Some(mut spool) = self.spool.take() else {
            *retry_at = None;
            return;
        };
        let mut ok = true;
        loop {
            let (events, unreadable) = match spool.oldest() {
                Ok(Some(seg)) => seg,
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(sink = self.config.name, "cannot read the spool: {e}");
                    ok = false;
                    break;
                }
            };
            SinkCounters::add(&self.counters.spool_unreadable, unreadable as usize);
            let mut written = 0;
            for chunk in events.chunks(limit) {
                if !self.write(chunk).await {
                    ok = false;
                    break;
                }
                written += chunk.len();
                SinkCounters::add(&self.counters.replayed, chunk.len());
            }
            if let Err(e) = spool.consumed(written, &events) {
                tracing::warn!(sink = self.config.name, "cannot update the spool: {e}");
                ok = false;
            }
            if !ok {
                break;
            }
        }
        self.spool = Some(spool);
        self.update_gauges();
        if ok {
            *retry_at = None;
            *backoff = self.retry_min;
        } else {
            *retry_at = Some(Instant::now() + *backoff);
            *backoff = (*backoff * 2).min(self.retry_max);
        }
    }

    fn update_gauges(&self) {
        let (events, bytes) = self
            .spool
            .as_ref()
            .map_or((0, 0), |s| (s.events(), s.bytes()));
        self.counters.spool_events.store(events, Ordering::Relaxed);
        self.counters.spool_bytes.store(bytes, Ordering::Relaxed);
    }

    async fn apply_retention(&self, keep: Duration) {
        let cutoff = self.clock.now() - keep;
        match self.sink.delete_before(cutoff).await {
            Ok(n) => SinkCounters::add(&self.counters.retention_deleted, n as usize),
            Err(e) => tracing::warn!(sink = self.config.name, "retention failed: {e}"),
        }
    }
}
