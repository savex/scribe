use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use scribe_core::Security;
use scribe_storage_api::{
    AlertState, Baseline, BaselineEntry, BoxFuture, EventQuery, EventSink, Health, Host, HostDelta,
    HostId, HostQuery, Page, Result, SinkCaps, StateStore, StorageError, StoreCaps, StoredEvent,
};

/// In-memory reference [`StateStore`]. Also proves the conformance suite itself is correct.
#[derive(Default)]
pub struct MemoryStore {
    hosts: Mutex<Vec<Host>>,
    ips: Mutex<HashMap<IpAddr, HostId>>,
    baselines: Mutex<HashMap<String, Vec<BaselineEntry>>>,
    alerts: Mutex<HashMap<String, AlertState>>,
}

impl MemoryStore {
    pub fn hosts(&self) -> Vec<Host> {
        self.hosts.lock().unwrap().clone()
    }

    pub fn host_for_ip(&self, ip: &IpAddr) -> Option<HostId> {
        self.ips.lock().unwrap().get(ip).copied()
    }
}

impl StateStore for MemoryStore {
    fn capabilities(&self) -> StoreCaps {
        StoreCaps::default()
    }

    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn upsert_host<'a>(&'a self, d: &'a HostDelta) -> BoxFuture<'a, Result<HostId>> {
        Box::pin(async move {
            let mut hosts = self.hosts.lock().unwrap();
            let idx = match hosts.iter().position(|h| h.name == d.name) {
                Some(idx) => idx,
                None => {
                    let id = hosts.len() as HostId + 1;
                    hosts.push(Host {
                        id,
                        name: d.name.clone(),
                        first_seen: d.seen_at,
                        last_seen: d.seen_at,
                        conn_count: 0,
                        req_count: 0,
                        bytes_out: 0,
                        tls_seen: false,
                        plaintext_seen: false,
                    });
                    hosts.len() - 1
                }
            };
            let h = &mut hosts[idx];
            h.last_seen = h.last_seen.max(d.seen_at);
            h.conn_count += d.connections;
            h.req_count += d.requests;
            h.bytes_out += d.bytes_out;
            h.tls_seen |= d.security == Security::Tls;
            h.plaintext_seen |= d.security == Security::Plaintext;
            Ok(h.id)
        })
    }

    fn get_host<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Host>>> {
        Box::pin(async move {
            Ok(self
                .hosts
                .lock()
                .unwrap()
                .iter()
                .find(|h| h.name == name)
                .cloned())
        })
    }

    fn link_ip(&self, host: HostId, ip: IpAddr, _ttl: Duration) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.ips.lock().unwrap().insert(ip, host);
            Ok(())
        })
    }

    fn list_hosts<'a>(&'a self, q: &'a HostQuery) -> BoxFuture<'a, Result<Page<Host>>> {
        Box::pin(async move {
            let hosts = self.hosts.lock().unwrap();
            let matching: Vec<Host> = hosts
                .iter()
                .filter(|h| {
                    q.name_contains
                        .as_deref()
                        .map_or(true, |s| h.name.contains(s))
                })
                .cloned()
                .collect();
            let total = matching.len() as u64;
            let items = matching
                .into_iter()
                .skip(q.offset)
                .take(q.limit.unwrap_or(usize::MAX))
                .collect();
            Ok(Page {
                items,
                total: Some(total),
            })
        })
    }

    fn baseline<'a>(&'a self, profile: &'a str) -> BoxFuture<'a, Result<Baseline>> {
        Box::pin(async move {
            let entries = self
                .baselines
                .lock()
                .unwrap()
                .get(profile)
                .cloned()
                .unwrap_or_default();
            Ok(Baseline {
                profile: profile.to_owned(),
                entries,
            })
        })
    }

    fn add_to_baseline<'a>(
        &'a self,
        profile: &'a str,
        entry: &'a BaselineEntry,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut baselines = self.baselines.lock().unwrap();
            let entries = baselines.entry(profile.to_owned()).or_default();
            if !entries.iter().any(|e| e.host == entry.host) {
                entries.push(entry.clone());
            }
            Ok(())
        })
    }

    fn put_alert_state<'a>(&'a self, state: &'a AlertState) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.alerts
                .lock()
                .unwrap()
                .insert(state.key.clone(), state.clone());
            Ok(())
        })
    }

    fn get_alert_state<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<AlertState>>> {
        Box::pin(async move { Ok(self.alerts.lock().unwrap().get(key).cloned()) })
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(async { Health::Ok })
    }
}

/// In-memory reference [`EventSink`] that supports queries.
#[derive(Default)]
pub struct MemorySink {
    events: Mutex<Vec<StoredEvent>>,
}

impl MemorySink {
    pub fn events(&self) -> Vec<StoredEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl EventSink for MemorySink {
    fn name(&self) -> &str {
        "memory"
    }

    fn capabilities(&self) -> SinkCaps {
        SinkCaps {
            queryable: true,
            native_retention: false,
            max_batch: usize::MAX,
        }
    }

    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn write_batch<'a>(&'a self, batch: &'a [StoredEvent]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.events.lock().unwrap().extend_from_slice(batch);
            Ok(())
        })
    }

    fn query<'a>(&'a self, q: &'a EventQuery) -> BoxFuture<'a, Result<Page<StoredEvent>>> {
        Box::pin(async move {
            let events = self.events.lock().unwrap();
            let items = events
                .iter()
                .filter(|e| q.kinds.is_empty() || q.kinds.contains(&e.kind()))
                .filter(|e| q.since.map_or(true, |t| e.ts() >= t))
                .filter(|e| q.until.map_or(true, |t| e.ts() < t))
                .skip(q.offset)
                .take(q.limit.unwrap_or(usize::MAX))
                .cloned()
                .collect();
            Ok(Page { items, total: None })
        })
    }

    fn flush(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(async { Health::Ok })
    }
}

/// Wraps a sink and fails or slows down writes on command, for outage and backpressure tests.
pub struct FaultySink<S> {
    inner: S,
    failing: AtomicBool,
    delay: Mutex<Duration>,
    attempts: AtomicUsize,
}

impl<S: EventSink> FaultySink<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            failing: AtomicBool::new(false),
            delay: Mutex::new(Duration::ZERO),
            attempts: AtomicUsize::new(0),
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }

    /// Blocks the calling thread for `delay` on every write.
    pub fn set_delay(&self, delay: Duration) {
        *self.delay.lock().unwrap() = delay;
    }

    /// Number of `write_batch` calls, including failed ones.
    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}

impl<S: EventSink> EventSink for FaultySink<S> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> SinkCaps {
        self.inner.capabilities()
    }

    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.migrate()
    }

    fn write_batch<'a>(&'a self, batch: &'a [StoredEvent]) -> BoxFuture<'a, Result<()>> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let delay = *self.delay.lock().unwrap();
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        if self.failing.load(Ordering::SeqCst) {
            return Box::pin(async {
                Err(StorageError::Backend(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "injected failure",
                ))))
            });
        }
        self.inner.write_batch(batch)
    }

    fn query<'a>(&'a self, q: &'a EventQuery) -> BoxFuture<'a, Result<Page<StoredEvent>>> {
        self.inner.query(q)
    }

    fn flush(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.flush()
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        if self.failing.load(Ordering::SeqCst) {
            return Box::pin(async { Health::Down("injected failure".into()) });
        }
        self.inner.health()
    }
}
