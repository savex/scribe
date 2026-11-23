use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use scribe_core::Security;
use scribe_storage_api::{
    AlertState, Baseline, BaselineEntry, BoxFuture, EventQuery, EventSink, Health, Host, HostDelta,
    HostId, HostQuery, ModuleState, Page, ProcessHost, Result, SinkCaps, StateStore, StorageError,
    StoreCaps, StoredEvent,
};

/// In-memory reference [`StateStore`]. Also proves the conformance suite itself is correct.
#[derive(Default)]
pub struct MemoryStore {
    hosts: Mutex<Vec<Host>>,
    ips: Mutex<HashMap<IpAddr, HostId>>,
    baselines: Mutex<HashMap<String, Vec<BaselineEntry>>>,
    alerts: Mutex<HashMap<String, AlertState>>,
    modules: Mutex<HashMap<String, ModuleState>>,
    process_hosts: Mutex<Vec<ProcessHost>>,
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
                        unresolved: false,
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
            h.unresolved |= d.unresolved;
            let id = h.id;
            drop(hosts);
            if let Some(process) = &d.process {
                let mut ph = self.process_hosts.lock().unwrap();
                let row = match ph
                    .iter()
                    .position(|r| &r.process == process && r.host == d.name)
                {
                    Some(i) => &mut ph[i],
                    None => {
                        ph.push(ProcessHost {
                            process: process.clone(),
                            host: d.name.clone(),
                            first_seen: d.seen_at,
                            last_seen: d.seen_at,
                            conn_count: 0,
                            req_count: 0,
                            bytes_out: 0,
                        });
                        ph.last_mut().unwrap()
                    }
                };
                row.first_seen = row.first_seen.min(d.seen_at);
                row.last_seen = row.last_seen.max(d.seen_at);
                row.conn_count += d.connections;
                row.req_count += d.requests;
                row.bytes_out += d.bytes_out;
            }
            Ok(id)
        })
    }

    fn process_hosts<'a>(
        &'a self,
        process: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Vec<ProcessHost>>> {
        Box::pin(async move {
            let mut rows: Vec<ProcessHost> = self
                .process_hosts
                .lock()
                .unwrap()
                .iter()
                .filter(|r| process.is_none_or(|p| r.process == p))
                .cloned()
                .collect();
            rows.sort_by(|a, b| (&a.process, &a.host).cmp(&(&b.process, &b.host)));
            Ok(rows)
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
                        .is_none_or(|s| h.name.contains(s))
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

    fn remove_from_baseline<'a>(
        &'a self,
        profile: &'a str,
        host: &'a str,
    ) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            let mut baselines = self.baselines.lock().unwrap();
            let Some(entries) = baselines.get_mut(profile) else {
                return Ok(false);
            };
            let before = entries.len();
            entries.retain(|e| e.host != host);
            Ok(entries.len() < before)
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

    fn module_state<'a>(&'a self, module: &'a str) -> BoxFuture<'a, Result<ModuleState>> {
        Box::pin(async move {
            Ok(self
                .modules
                .lock()
                .unwrap()
                .get(module)
                .cloned()
                .unwrap_or_default())
        })
    }

    fn put_module_state<'a>(
        &'a self,
        module: &'a str,
        key: &'a str,
        value: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.modules
                .lock()
                .unwrap()
                .entry(module.to_owned())
                .or_default()
                .insert(key.to_owned(), value.clone());
            Ok(())
        })
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
                .filter(|e| q.since.is_none_or(|t| e.ts() >= t))
                .filter(|e| q.until.is_none_or(|t| e.ts() < t))
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

    fn delete_before(&self, cutoff: std::time::SystemTime) -> BoxFuture<'_, Result<u64>> {
        Box::pin(async move {
            let mut events = self.events.lock().unwrap();
            let before = events.len();
            events.retain(|e| e.ts() >= cutoff);
            Ok((before - events.len()) as u64)
        })
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
                Err(StorageError::Backend(Box::new(std::io::Error::other(
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

    fn delete_before(&self, cutoff: std::time::SystemTime) -> BoxFuture<'_, Result<u64>> {
        self.inner.delete_before(cutoff)
    }
}
