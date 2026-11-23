//! A least-recently-used cache of hosts and baselines in front of the state store
//! (`storage.cache`, specs 9.1). Reads that hit the cache don't touch the store, so the hot path
//! keeps working while the store is slow or down; writes go through and update cached entries.
//!
//! Hosts are evicted, least recently used first, when either `max_hosts` or `max_memory` is
//! exceeded; evicted hosts are read back from the store on the next miss. Baselines (a few per
//! install) are cached whole and not counted against the limits.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scribe_core::Security;
use scribe_storage_api::{
    AlertState, Baseline, BaselineEntry, BoxFuture, Health, Host, HostDelta, HostId, HostQuery,
    ModuleState, Page, ProcessHost, Result, StateStore, StoreCaps,
};
use serde_json::Value;

/// Limits of the host cache (`storage.cache`).
#[derive(Debug, Clone, Copy)]
pub struct CacheLimits {
    pub max_hosts: u64,
    pub max_memory: u64,
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_hosts: 50_000,
            max_memory: 32 << 20,
        }
    }
}

/// Live cache counters (`scribe daemon status`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheStatus {
    pub hosts: u64,
    pub bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

fn host_size(h: &Host) -> u64 {
    (std::mem::size_of::<Host>() + h.name.len() * 2 + 64) as u64
}

#[derive(Default)]
struct Lru {
    hosts: HashMap<String, (Host, u64)>,
    order: BTreeMap<u64, String>,
    tick: u64,
    bytes: u64,
    baselines: HashMap<String, Baseline>,
}

impl Lru {
    fn touch(&mut self, name: &str) -> Option<Host> {
        self.tick += 1;
        let tick = self.tick;
        let (host, used) = self.hosts.get_mut(name)?;
        self.order.remove(used);
        *used = tick;
        self.order.insert(tick, name.to_owned());
        Some(host.clone())
    }

    fn put(&mut self, host: Host) {
        self.remove(&host.name.clone());
        self.tick += 1;
        self.bytes += host_size(&host);
        self.order.insert(self.tick, host.name.clone());
        self.hosts.insert(host.name.clone(), (host, self.tick));
    }

    fn remove(&mut self, name: &str) {
        if let Some((host, used)) = self.hosts.remove(name) {
            self.order.remove(&used);
            self.bytes -= host_size(&host);
        }
    }

    /// Evict until within limits; returns how many were evicted.
    fn shrink(&mut self, limits: CacheLimits) -> u64 {
        let mut evicted = 0;
        while self.hosts.len() as u64 > limits.max_hosts || self.bytes > limits.max_memory {
            let Some((_, name)) = self.order.pop_first() else {
                break;
            };
            if let Some((host, _)) = self.hosts.remove(&name) {
                self.bytes -= host_size(&host);
            }
            evicted += 1;
        }
        evicted
    }
}

/// Apply a counter delta to a cached host, the same way the store does.
fn apply(host: &mut Host, d: &HostDelta) {
    host.first_seen = host.first_seen.min(d.seen_at);
    host.last_seen = host.last_seen.max(d.seen_at);
    host.conn_count += d.connections;
    host.req_count += d.requests;
    host.bytes_out += d.bytes_out;
    host.tls_seen |= d.security == Security::Tls;
    host.plaintext_seen |= d.security == Security::Plaintext;
    host.unresolved |= d.unresolved;
}

/// A [`StateStore`] with the host and baseline cache in front.
pub struct CachedState {
    inner: Arc<dyn StateStore>,
    limits: CacheLimits,
    lru: Mutex<Lru>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl CachedState {
    pub fn new(inner: Arc<dyn StateStore>, limits: CacheLimits) -> Self {
        Self {
            inner,
            limits,
            lru: Mutex::new(Lru::default()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    pub fn status(&self) -> CacheStatus {
        let lru = self.lru.lock().unwrap();
        CacheStatus {
            hosts: lru.hosts.len() as u64,
            bytes: lru.bytes,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }

    /// Forget everything (`scribe daemon reset --caches`); entries refill from the store.
    pub fn clear(&self) {
        *self.lru.lock().unwrap() = Lru::default();
    }

    fn insert(&self, host: Host) {
        let mut lru = self.lru.lock().unwrap();
        lru.put(host);
        let n = lru.shrink(self.limits);
        self.evictions.fetch_add(n, Ordering::Relaxed);
    }
}

impl StateStore for CachedState {
    fn capabilities(&self) -> StoreCaps {
        self.inner.capabilities()
    }

    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.migrate()
    }

    fn upsert_host<'a>(&'a self, delta: &'a HostDelta) -> BoxFuture<'a, Result<HostId>> {
        Box::pin(async move {
            let id = self.inner.upsert_host(delta).await?;
            let mut lru = self.lru.lock().unwrap();
            if let Some((host, _)) = lru.hosts.get_mut(&delta.name) {
                apply(host, delta);
                if id != 0 {
                    host.id = id;
                }
            }
            Ok(id)
        })
    }

    fn get_host<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Host>>> {
        Box::pin(async move {
            if let Some(host) = self.lru.lock().unwrap().touch(name) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(host));
            }
            self.misses.fetch_add(1, Ordering::Relaxed);
            let found = self.inner.get_host(name).await?;
            if let Some(host) = &found {
                self.insert(host.clone());
            }
            Ok(found)
        })
    }

    fn link_ip(&self, host: HostId, ip: IpAddr, ttl: Duration) -> BoxFuture<'_, Result<()>> {
        self.inner.link_ip(host, ip, ttl)
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
        Box::pin(async move {
            if let Some(b) = self.lru.lock().unwrap().baselines.get(profile) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(b.clone());
            }
            self.misses.fetch_add(1, Ordering::Relaxed);
            let b = self.inner.baseline(profile).await?;
            self.lru
                .lock()
                .unwrap()
                .baselines
                .insert(profile.to_owned(), b.clone());
            Ok(b)
        })
    }

    fn add_to_baseline<'a>(
        &'a self,
        profile: &'a str,
        entry: &'a BaselineEntry,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.inner.add_to_baseline(profile, entry).await?;
            if let Some(b) = self.lru.lock().unwrap().baselines.get_mut(profile) {
                if !b.contains(&entry.host) {
                    b.entries.push(entry.clone());
                }
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
            let removed = self.inner.remove_from_baseline(profile, host).await?;
            if let Some(b) = self.lru.lock().unwrap().baselines.get_mut(profile) {
                b.entries.retain(|e| e.host != host);
            }
            Ok(removed)
        })
    }

    fn put_alert_state<'a>(&'a self, state: &'a AlertState) -> BoxFuture<'a, Result<()>> {
        self.inner.put_alert_state(state)
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
        self.inner.put_module_state(module, key, value)
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        self.inner.health()
    }
}
