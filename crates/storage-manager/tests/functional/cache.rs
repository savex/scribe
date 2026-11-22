//! The host and baseline cache: hits, write-through updates, LRU eviction, outages, clear.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use scribe_core::Security;
use scribe_storage_api::{BaselineEntry, EntrySource, HostDelta, StateStore};
use scribe_storage_manager::{CacheLimits, CachedState};
use scribe_test_support::MemoryStore;

fn delta(name: &str, secs: u64, security: Security) -> HostDelta {
    HostDelta {
        name: name.into(),
        seen_at: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
        connections: 1,
        requests: 0,
        bytes_out: 100,
        security,
        unresolved: false,
        process: None,
    }
}

fn cached(limits: CacheLimits) -> (Arc<MemoryStore>, CachedState) {
    let store = Arc::new(MemoryStore::default());
    (store.clone(), CachedState::new(store, limits))
}

#[tokio::test]
async fn reads_hit_the_cache_and_writes_keep_it_current() {
    let (_store, c) = cached(CacheLimits::default());
    c.upsert_host(&delta("api.example.com", 10, Security::Tls))
        .await
        .unwrap();
    let first = c.get_host("api.example.com").await.unwrap().unwrap();
    assert_eq!(c.status().misses, 1);
    c.upsert_host(&delta("api.example.com", 5, Security::Plaintext))
        .await
        .unwrap();
    let again = c.get_host("api.example.com").await.unwrap().unwrap();
    assert_eq!(c.status().hits, 1);
    assert_eq!(again.id, first.id);
    assert_eq!((again.conn_count, again.bytes_out), (2, 200));
    assert_eq!(
        again.first_seen,
        SystemTime::UNIX_EPOCH + Duration::from_secs(5)
    );
    assert!(again.tls_seen && again.plaintext_seen);
    assert_eq!(c.get_host("missing.example.com").await.unwrap(), None);
}

#[tokio::test]
async fn the_least_recently_used_host_is_evicted_first() {
    let (_store, c) = cached(CacheLimits {
        max_hosts: 2,
        max_memory: u64::MAX,
    });
    for name in ["a.example.com", "b.example.com", "c.example.com"] {
        c.upsert_host(&delta(name, 1, Security::Tls)).await.unwrap();
    }
    c.get_host("a.example.com").await.unwrap();
    c.get_host("b.example.com").await.unwrap();
    c.get_host("a.example.com").await.unwrap(); // a is now the most recent
    c.get_host("c.example.com").await.unwrap(); // evicts b
    let s = c.status();
    assert_eq!((s.hosts, s.evictions), (2, 1));
    let misses = s.misses;
    c.get_host("a.example.com").await.unwrap();
    assert_eq!(c.status().misses, misses, "a stayed cached");
    c.get_host("b.example.com").await.unwrap();
    assert_eq!(c.status().misses, misses + 1, "b was evicted and read back");
}

#[tokio::test]
async fn the_memory_limit_bounds_the_cache() {
    let (_store, c) = cached(CacheLimits {
        max_hosts: u64::MAX,
        max_memory: 2_000,
    });
    for i in 0..100 {
        let name = format!("h{i}.example.com");
        c.upsert_host(&delta(&name, 1, Security::Tls))
            .await
            .unwrap();
        c.get_host(&name).await.unwrap();
    }
    let s = c.status();
    assert!(s.bytes <= 2_000, "{s:?}");
    assert!(s.evictions > 0);
}

#[tokio::test]
async fn baselines_are_cached_and_kept_current() {
    let (store, c) = cached(CacheLimits::default());
    let entry = |host: &str| BaselineEntry {
        host: host.into(),
        source: EntrySource::Manual,
        added_at: SystemTime::UNIX_EPOCH,
    };
    store
        .add_to_baseline("work", &entry("a.example.com"))
        .await
        .unwrap();
    assert!(c.baseline("work").await.unwrap().contains("a.example.com"));
    c.add_to_baseline("work", &entry("b.example.com"))
        .await
        .unwrap();
    let b = c.baseline("work").await.unwrap();
    assert!(b.contains("b.example.com"));
    assert_eq!(c.status().hits, 1);
}

#[tokio::test]
async fn clear_empties_the_cache() {
    let (_store, c) = cached(CacheLimits::default());
    c.upsert_host(&delta("api.example.com", 1, Security::Tls))
        .await
        .unwrap();
    c.get_host("api.example.com").await.unwrap();
    c.clear();
    assert_eq!(c.status().hosts, 0);
    assert!(
        c.get_host("api.example.com").await.unwrap().is_some(),
        "refills from the store"
    );
}
