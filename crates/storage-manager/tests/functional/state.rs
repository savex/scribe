//! The state-store outage buffer: order, limits, host-id links, health, poison writes.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use scribe_core::Security;
use scribe_storage_api::{
    AlertState, Baseline, BaselineEntry, BoxFuture, EntrySource, Health, Host, HostDelta, HostId,
    HostQuery, ModuleState, Page, Result, StateStore, StorageError, StoreCaps,
};
use scribe_storage_manager::{BufferLimits, BufferedState};
use scribe_test_support::MemoryStore;
use serde_json::{json, Value};

/// A `MemoryStore` that can be switched off; host names starting with `bad.` are rejected as
/// unstorable data.
#[derive(Default)]
struct Switchable {
    inner: MemoryStore,
    down: AtomicBool,
}

impl Switchable {
    fn check(&self) -> Result<()> {
        if self.down.load(Ordering::SeqCst) {
            Err(StorageError::backend(std::io::Error::other("store down")))
        } else {
            Ok(())
        }
    }
}

macro_rules! guarded {
    ($self:ident, $call:expr) => {
        Box::pin(async move {
            $self.check()?;
            $call.await
        })
    };
}

impl StateStore for Switchable {
    fn capabilities(&self) -> StoreCaps {
        StoreCaps::default()
    }
    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn upsert_host<'a>(&'a self, d: &'a HostDelta) -> BoxFuture<'a, Result<HostId>> {
        Box::pin(async move {
            self.check()?;
            if d.name.starts_with("bad.") {
                return Err(StorageError::Data("name rejected".into()));
            }
            self.inner.upsert_host(d).await
        })
    }
    fn get_host<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Host>>> {
        guarded!(self, self.inner.get_host(name))
    }
    fn link_ip(&self, host: HostId, ip: IpAddr, ttl: Duration) -> BoxFuture<'_, Result<()>> {
        guarded!(self, self.inner.link_ip(host, ip, ttl))
    }
    fn list_hosts<'a>(&'a self, q: &'a HostQuery) -> BoxFuture<'a, Result<Page<Host>>> {
        guarded!(self, self.inner.list_hosts(q))
    }
    fn baseline<'a>(&'a self, p: &'a str) -> BoxFuture<'a, Result<Baseline>> {
        guarded!(self, self.inner.baseline(p))
    }
    fn add_to_baseline<'a>(
        &'a self,
        p: &'a str,
        e: &'a BaselineEntry,
    ) -> BoxFuture<'a, Result<()>> {
        guarded!(self, self.inner.add_to_baseline(p, e))
    }
    fn remove_from_baseline<'a>(&'a self, p: &'a str, h: &'a str) -> BoxFuture<'a, Result<bool>> {
        guarded!(self, self.inner.remove_from_baseline(p, h))
    }
    fn put_alert_state<'a>(&'a self, s: &'a AlertState) -> BoxFuture<'a, Result<()>> {
        guarded!(self, self.inner.put_alert_state(s))
    }
    fn get_alert_state<'a>(&'a self, k: &'a str) -> BoxFuture<'a, Result<Option<AlertState>>> {
        guarded!(self, self.inner.get_alert_state(k))
    }
    fn module_state<'a>(&'a self, m: &'a str) -> BoxFuture<'a, Result<ModuleState>> {
        guarded!(self, self.inner.module_state(m))
    }
    fn put_module_state<'a>(
        &'a self,
        m: &'a str,
        k: &'a str,
        v: &'a Value,
    ) -> BoxFuture<'a, Result<()>> {
        guarded!(self, self.inner.put_module_state(m, k, v))
    }
    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(async { Health::Ok })
    }
}

fn delta(name: &str, bytes: u64) -> HostDelta {
    HostDelta {
        name: name.into(),
        seen_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        connections: 1,
        requests: 0,
        bytes_out: bytes,
        security: Security::Tls,
        unresolved: false,
        process: None,
    }
}

fn setup(limits: BufferLimits) -> (Arc<Switchable>, BufferedState) {
    let store = Arc::new(Switchable::default());
    let buffered = BufferedState::new(store.clone(), limits);
    (store, buffered)
}

#[tokio::test]
async fn writes_pass_through_while_the_store_works() {
    let (store, s) = setup(BufferLimits::default());
    let id = s.upsert_host(&delta("api.example.com", 10)).await.unwrap();
    assert_ne!(id, 0);
    assert_eq!(store.inner.hosts().len(), 1);
    assert_eq!(s.status().buffered, 0);
    assert_eq!(s.health().await, Health::Ok);
}

#[tokio::test]
async fn an_outage_buffers_writes_and_replays_them_in_order() {
    let (store, s) = setup(BufferLimits::default());
    store.down.store(true, Ordering::SeqCst);
    for bytes in [10, 20, 30] {
        assert_eq!(
            s.upsert_host(&delta("api.example.com", bytes))
                .await
                .unwrap(),
            0
        );
    }
    s.put_module_state("url", "requests", &json!(3))
        .await
        .unwrap();
    let entry = BaselineEntry {
        host: "api.example.com".into(),
        source: EntrySource::Learned,
        added_at: SystemTime::UNIX_EPOCH,
    };
    s.add_to_baseline("default", &entry).await.unwrap();
    assert_eq!(s.status().buffered, 5);
    assert!(matches!(s.health().await, Health::Degraded(_)));
    assert!(!s.replay().await, "still down");

    // Back up: a new write still waits behind the buffer until replay.
    store.down.store(false, Ordering::SeqCst);
    s.upsert_host(&delta("api.example.com", 40)).await.unwrap();
    assert!(
        store.inner.hosts().is_empty(),
        "no write overtakes the buffer"
    );
    assert!(s.replay().await);
    let host = store.inner.hosts().pop().unwrap();
    assert_eq!((host.conn_count, host.bytes_out), (4, 100));
    assert_eq!(s.module_state("url").await.unwrap()["requests"], json!(3));
    assert!(s
        .baseline("default")
        .await
        .unwrap()
        .contains("api.example.com"));
    let st = s.status();
    assert_eq!((st.buffered, st.replayed, st.dropped), (0, 6, 0));
    assert!(st.last_error.unwrap().contains("store down"));
}

#[tokio::test]
async fn a_full_buffer_drops_the_oldest_writes() {
    let (store, s) = setup(BufferLimits {
        max_events: 3,
        max_memory: u64::MAX,
    });
    store.down.store(true, Ordering::SeqCst);
    for i in 0..5 {
        s.upsert_host(&delta(&format!("h{i}.example.com"), 1))
            .await
            .unwrap();
    }
    assert_eq!((s.status().buffered, s.status().dropped), (3, 2));
    store.down.store(false, Ordering::SeqCst);
    assert!(s.replay().await);
    let mut names: Vec<_> = store.inner.hosts().into_iter().map(|h| h.name).collect();
    names.sort();
    assert_eq!(
        names,
        ["h2.example.com", "h3.example.com", "h4.example.com"]
    );
}

#[tokio::test]
async fn the_memory_limit_also_drops_the_oldest() {
    let (store, s) = setup(BufferLimits {
        max_events: u64::MAX,
        max_memory: 600,
    });
    store.down.store(true, Ordering::SeqCst);
    for i in 0..50 {
        s.upsert_host(&delta(&format!("h{i}.example.com"), 1))
            .await
            .unwrap();
    }
    let st = s.status();
    assert!(st.buffer_bytes <= 600, "{st:?}");
    assert_eq!(st.buffered + st.dropped, 50);
}

#[tokio::test]
async fn ip_links_follow_their_buffered_host() {
    let (store, s) = setup(BufferLimits::default());
    store.down.store(true, Ordering::SeqCst);
    let id = s.upsert_host(&delta("cdn.example.com", 1)).await.unwrap();
    assert_eq!(id, 0, "no id while buffered");
    let ip: IpAddr = "192.0.2.50".parse().unwrap();
    s.link_ip(id, ip, Duration::from_secs(60)).await.unwrap();
    store.down.store(false, Ordering::SeqCst);
    assert!(s.replay().await);
    let real = store.inner.hosts()[0].id;
    assert_eq!(store.inner.host_for_ip(&ip), Some(real));
}

#[tokio::test]
async fn writes_that_can_never_be_stored_are_dropped_on_replay() {
    let (store, s) = setup(BufferLimits::default());
    store.down.store(true, Ordering::SeqCst);
    s.upsert_host(&delta("bad.example.com", 1)).await.unwrap();
    s.upsert_host(&delta("good.example.com", 1)).await.unwrap();
    store.down.store(false, Ordering::SeqCst);
    assert!(s.replay().await, "the poison write doesn't block the rest");
    assert_eq!(s.status().rejected, 1);
    assert_eq!(store.inner.hosts()[0].name, "good.example.com");
}

#[tokio::test]
async fn data_errors_while_healthy_go_back_to_the_caller() {
    let (_store, s) = setup(BufferLimits::default());
    let err = s
        .upsert_host(&delta("bad.example.com", 1))
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::Data(_)));
    assert_eq!(s.status().buffered, 0, "only outages are buffered");
}
