//! In-memory reference backend that keeps the suite itself honest.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use scribe_core::Security;
use scribe_storage_api::{
    AlertState, Baseline, BaselineEntry, BoxFuture, EventQuery, EventSink, Health, Host,
    HostDelta, HostId, HostQuery, Page, Result, SinkCaps, StateStore, StoreCaps, StoredEvent,
};
use scribe_storage_conformance::{block_on, event_sink_suite, state_store_suite};

#[derive(Default)]
struct MemoryStore {
    hosts: Mutex<Vec<Host>>,
    baselines: Mutex<HashMap<String, Vec<BaselineEntry>>>,
    alerts: Mutex<HashMap<String, AlertState>>,
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
            Ok(self.hosts.lock().unwrap().iter().find(|h| h.name == name).cloned())
        })
    }

    fn link_ip(&self, _host: HostId, _ip: IpAddr, _ttl: Duration) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn list_hosts<'a>(&'a self, q: &'a HostQuery) -> BoxFuture<'a, Result<Page<Host>>> {
        Box::pin(async move {
            let hosts = self.hosts.lock().unwrap();
            let matching: Vec<Host> = hosts
                .iter()
                .filter(|h| q.name_contains.as_deref().map_or(true, |s| h.name.contains(s)))
                .cloned()
                .collect();
            let total = matching.len() as u64;
            let items =
                matching.into_iter().skip(q.offset).take(q.limit.unwrap_or(usize::MAX)).collect();
            Ok(Page { items, total: Some(total) })
        })
    }

    fn baseline<'a>(&'a self, profile: &'a str) -> BoxFuture<'a, Result<Baseline>> {
        Box::pin(async move {
            let entries =
                self.baselines.lock().unwrap().get(profile).cloned().unwrap_or_default();
            Ok(Baseline { profile: profile.to_owned(), entries })
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
            self.alerts.lock().unwrap().insert(state.key.clone(), state.clone());
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

#[derive(Default)]
struct MemorySink {
    events: Mutex<Vec<StoredEvent>>,
}

impl EventSink for MemorySink {
    fn name(&self) -> &str {
        "memory"
    }

    fn capabilities(&self) -> SinkCaps {
        SinkCaps { queryable: true, native_retention: false, max_batch: usize::MAX }
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

#[test]
fn reference_state_store_conforms() {
    block_on(state_store_suite(&MemoryStore::default()));
}

#[test]
fn reference_event_sink_conforms() {
    block_on(event_sink_suite(&MemorySink::default()));
}
