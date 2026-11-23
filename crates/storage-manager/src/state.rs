//! The state store with an in-memory outage buffer (FR-25, specs 8.4).
//!
//! Writes go straight to the state store while it works. When a write fails, it and every later
//! write wait in a bounded in-memory buffer, in order, and a background task replays them with
//! back-off. When the buffer is full, the oldest write is dropped to make room (counted).
//!
//! - A buffered `upsert_host` returns host id `0`; a following `link_ip(0, …)` is kept with that
//!   host's name and linked to its real id on replay.
//! - A write that fails on replay with `StorageError::Data` can never succeed; it is dropped
//!   (counted) so it doesn't block the writes behind it.
//! - Reads go to the state store; the host cache (next step) answers while it is down.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scribe_storage_api::{
    AlertState, Baseline, BaselineEntry, BoxFuture, Health, Host, HostDelta, HostId, HostQuery,
    ModuleState, Page, ProcessHost, Result, StateStore, StorageError, StoreCaps,
};
use serde_json::Value;

/// Limits of the outage buffer (`storage.buffer`).
#[derive(Debug, Clone, Copy)]
pub struct BufferLimits {
    pub max_events: u64,
    pub max_memory: u64,
}

impl Default for BufferLimits {
    fn default() -> Self {
        Self {
            max_events: 50_000,
            max_memory: 32 << 20,
        }
    }
}

#[derive(Debug, Clone)]
enum Write {
    UpsertHost(HostDelta),
    LinkIp {
        host: HostId,
        name: Option<String>,
        ip: IpAddr,
        ttl: Duration,
    },
    AddToBaseline(String, BaselineEntry),
    RemoveFromBaseline(String, String),
    PutAlertState(AlertState),
    PutModuleState(String, String, Value),
}

impl Write {
    /// Rough memory use, for `max_memory`.
    fn size(&self) -> u64 {
        let text = match self {
            Write::UpsertHost(d) => d.name.len(),
            Write::LinkIp { name, .. } => name.as_ref().map_or(0, String::len),
            Write::AddToBaseline(p, e) => p.len() + e.host.len(),
            Write::RemoveFromBaseline(p, h) => p.len() + h.len(),
            Write::PutAlertState(a) => a.key.len(),
            Write::PutModuleState(m, k, v) => m.len() + k.len() + v.to_string().len(),
        };
        (std::mem::size_of::<Write>() + text) as u64
    }
}

/// Live counters of the state store side (`scribe daemon status`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateStatus {
    /// Writes waiting in the buffer now.
    pub buffered: u64,
    pub buffer_bytes: u64,
    /// Writes dropped because the buffer was full.
    pub dropped: u64,
    /// Writes dropped on replay because they can never succeed.
    pub rejected: u64,
    pub replayed: u64,
    pub last_error: Option<String>,
}

#[derive(Default)]
struct Buffer {
    writes: VecDeque<Write>,
    bytes: u64,
    last_upsert: Option<String>,
}

/// A [`StateStore`] that keeps writes while the real one is down.
pub struct BufferedState {
    inner: Arc<dyn StateStore>,
    limits: BufferLimits,
    buffer: Mutex<Buffer>,
    /// Serializes writes and replay, so writes reach the store in order.
    gate: tokio::sync::Mutex<()>,
    dropped: AtomicU64,
    rejected: AtomicU64,
    replayed: AtomicU64,
    last_error: Mutex<Option<String>>,
}

/// Errors that mean "the store is unavailable" (worth buffering), as opposed to a write that
/// can never succeed (`Data`) or an operation the backend lacks.
fn is_outage(e: &StorageError) -> bool {
    matches!(e, StorageError::Backend(_) | StorageError::Config(_))
}

impl BufferedState {
    pub fn new(inner: Arc<dyn StateStore>, limits: BufferLimits) -> Self {
        Self {
            inner,
            limits,
            buffer: Mutex::new(Buffer::default()),
            gate: tokio::sync::Mutex::new(()),
            dropped: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            replayed: AtomicU64::new(0),
            last_error: Mutex::new(None),
        }
    }

    pub fn status(&self) -> StateStatus {
        let b = self.buffer.lock().unwrap();
        StateStatus {
            buffered: b.writes.len() as u64,
            buffer_bytes: b.bytes,
            dropped: self.dropped.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            replayed: self.replayed.load(Ordering::Relaxed),
            last_error: self.last_error.lock().unwrap().clone(),
        }
    }

    pub fn is_buffering(&self) -> bool {
        !self.buffer.lock().unwrap().writes.is_empty()
    }

    fn push(&self, write: Write) {
        let mut b = self.buffer.lock().unwrap();
        if let Write::UpsertHost(d) = &write {
            b.last_upsert = Some(d.name.clone());
        }
        let size = write.size();
        b.bytes += size;
        b.writes.push_back(write);
        while b.writes.len() as u64 > self.limits.max_events || b.bytes > self.limits.max_memory {
            let Some(old) = b.writes.pop_front() else {
                break;
            };
            b.bytes -= old.size();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn note_error(&self, e: &StorageError) {
        *self.last_error.lock().unwrap() = Some(e.to_string());
    }

    async fn apply(&self, write: &Write) -> Result<HostId> {
        match write {
            Write::UpsertHost(d) => self.inner.upsert_host(d).await,
            Write::LinkIp {
                host,
                name,
                ip,
                ttl,
            } => {
                let id = match (host, name) {
                    (0, Some(name)) => match self.inner.get_host(name).await? {
                        Some(h) => h.id,
                        None => return Ok(0),
                    },
                    (id, _) => *id,
                };
                self.inner.link_ip(id, *ip, *ttl).await.map(|_| id)
            }
            Write::AddToBaseline(p, e) => self.inner.add_to_baseline(p, e).await.map(|_| 0),
            // 2 removed, 1 not listed (a buffered write returns 0).
            Write::RemoveFromBaseline(p, h) => self
                .inner
                .remove_from_baseline(p, h)
                .await
                .map(|removed| if removed { 2 } else { 1 }),
            Write::PutAlertState(a) => self.inner.put_alert_state(a).await.map(|_| 0),
            Write::PutModuleState(m, k, v) => self.inner.put_module_state(m, k, v).await.map(|_| 0),
        }
    }

    /// Write now if nothing is buffered, else (or on an outage) buffer it.
    async fn write(&self, mut write: Write) -> Result<HostId> {
        let _gate = self.gate.lock().await;
        if let Write::LinkIp { host: 0, name, .. } = &mut write {
            *name = self.buffer.lock().unwrap().last_upsert.clone();
        }
        if !self.is_buffering() {
            match self.apply(&write).await {
                Ok(id) => return Ok(id),
                Err(e) if is_outage(&e) => {
                    self.note_error(&e);
                    tracing::warn!("state store unavailable, buffering writes: {e}");
                }
                Err(e) => return Err(e),
            }
        }
        self.push(write);
        Ok(0)
    }

    /// Replay buffered writes in order. `true` when the buffer is empty afterwards.
    pub async fn replay(&self) -> bool {
        let _gate = self.gate.lock().await;
        loop {
            let next = self.buffer.lock().unwrap().writes.front().cloned();
            let Some(write) = next else {
                self.buffer.lock().unwrap().last_upsert = None;
                return true;
            };
            match self.apply(&write).await {
                Ok(_) => self.replayed.fetch_add(1, Ordering::Relaxed),
                Err(StorageError::Data(e)) => {
                    tracing::warn!("dropping a buffered state write that can't be stored: {e}");
                    self.rejected.fetch_add(1, Ordering::Relaxed)
                }
                Err(e) => {
                    self.note_error(&e);
                    return false;
                }
            };
            let mut b = self.buffer.lock().unwrap();
            if let Some(done) = b.writes.pop_front() {
                b.bytes -= done.size();
            }
        }
    }
}

impl StateStore for BufferedState {
    fn capabilities(&self) -> StoreCaps {
        self.inner.capabilities()
    }

    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.migrate()
    }

    fn upsert_host<'a>(&'a self, delta: &'a HostDelta) -> BoxFuture<'a, Result<HostId>> {
        Box::pin(self.write(Write::UpsertHost(delta.clone())))
    }

    fn get_host<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Host>>> {
        self.inner.get_host(name)
    }

    fn link_ip(&self, host: HostId, ip: IpAddr, ttl: Duration) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.write(Write::LinkIp {
                host,
                name: None,
                ip,
                ttl,
            })
            .await
            .map(|_| ())
        })
    }

    fn list_hosts<'a>(&'a self, query: &'a HostQuery) -> BoxFuture<'a, Result<Page<Host>>> {
        self.inner.list_hosts(query)
    }

    fn process_hosts<'a>(
        &'a self,
        process: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Vec<ProcessHost>>> {
        self.inner.process_hosts(process)
    }

    fn baseline<'a>(&'a self, profile: &'a str) -> BoxFuture<'a, Result<Baseline>> {
        self.inner.baseline(profile)
    }

    fn add_to_baseline<'a>(
        &'a self,
        profile: &'a str,
        entry: &'a BaselineEntry,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.write(Write::AddToBaseline(profile.to_owned(), entry.clone()))
                .await
                .map(|_| ())
        })
    }

    /// While the store is down the removal is buffered and reported as done.
    fn remove_from_baseline<'a>(
        &'a self,
        profile: &'a str,
        host: &'a str,
    ) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            self.write(Write::RemoveFromBaseline(
                profile.to_owned(),
                host.to_owned(),
            ))
            .await
            .map(|n| n != 1)
        })
    }

    fn put_alert_state<'a>(&'a self, state: &'a AlertState) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.write(Write::PutAlertState(state.clone()))
                .await
                .map(|_| ())
        })
    }

    fn get_alert_state<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<AlertState>>> {
        self.inner.get_alert_state(key)
    }

    fn alert_states(&self) -> BoxFuture<'_, Result<Vec<AlertState>>> {
        self.inner.alert_states()
    }

    fn module_state<'a>(&'a self, module: &'a str) -> BoxFuture<'a, Result<ModuleState>> {
        self.inner.module_state(module)
    }

    fn put_module_state<'a>(
        &'a self,
        module: &'a str,
        key: &'a str,
        value: &'a Value,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.write(Write::PutModuleState(
                module.to_owned(),
                key.to_owned(),
                value.clone(),
            ))
            .await
            .map(|_| ())
        })
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(async move {
            let s = self.status();
            if s.buffered > 0 {
                return Health::Degraded(format!(
                    "state store unavailable: {} writes buffered, {} dropped",
                    s.buffered, s.dropped
                ));
            }
            self.inner.health().await
        })
    }
}
