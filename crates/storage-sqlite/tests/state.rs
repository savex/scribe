//! SQLite-specific state store behaviour beyond the conformance suite.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use scribe_core::Security;
use scribe_storage_api::{BaselineEntry, EntrySource, HostDelta, HostQuery, StateStore};
use scribe_storage_conformance::block_on;
use scribe_storage_sqlite::SqliteStore;
use scribe_test_support::FakeClock;

fn store(dir: &Path) -> SqliteStore {
    let path = dir.join("state.db").to_string_lossy().into_owned();
    let s = SqliteStore::from_options(&HashMap::from([("path".to_owned(), path)])).unwrap();
    block_on(s.migrate()).unwrap();
    s
}

fn delta(name: &str, at_secs: u64) -> HostDelta {
    HostDelta {
        name: name.into(),
        seen_at: UNIX_EPOCH + Duration::from_secs(at_secs),
        connections: 1,
        requests: 0,
        bytes_out: 10,
        security: Security::Unknown,
    }
}

mod functional {
    use super::*;

    #[test]
    fn first_and_last_seen_follow_the_observations() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        block_on(s.upsert_host(&delta("api.example.com", 200))).unwrap();
        block_on(s.upsert_host(&delta("api.example.com", 100))).unwrap(); // late, older event
        block_on(s.upsert_host(&delta("api.example.com", 300))).unwrap();
        let h = block_on(s.get_host("api.example.com")).unwrap().unwrap();
        assert_eq!(h.first_seen, UNIX_EPOCH + Duration::from_secs(100));
        assert_eq!(h.last_seen, UNIX_EPOCH + Duration::from_secs(300));
        assert_eq!((h.conn_count, h.bytes_out), (3, 30));
        assert!(!h.tls_seen && !h.plaintext_seen);
    }

    #[test]
    fn listing_is_sorted_and_filters_literally() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        for name in [
            "b.example.com",
            "a.example.com",
            "a_b.example.net",
            "axb.example.net",
        ] {
            block_on(s.upsert_host(&delta(name, 1))).unwrap();
        }
        let names = |filter: Option<&str>| -> Vec<String> {
            block_on(s.list_hosts(&HostQuery {
                name_contains: filter.map(str::to_owned),
                ..Default::default()
            }))
            .unwrap()
            .items
            .into_iter()
            .map(|h| h.name)
            .collect()
        };
        assert_eq!(
            names(None),
            [
                "a.example.com",
                "a_b.example.net",
                "axb.example.net",
                "b.example.com"
            ]
        );
        assert_eq!(
            names(Some("a_b")),
            ["a_b.example.net"],
            "`_` is not a wildcard"
        );
        assert!(names(Some("%")).is_empty(), "`%` is not a wildcard");
        let page = block_on(s.list_hosts(&HostQuery {
            name_contains: None,
            offset: 3,
            limit: Some(10),
        }))
        .unwrap();
        assert_eq!(page.total, Some(4));
        assert_eq!(page.items.len(), 1);
    }

    #[test]
    fn baselines_keep_the_first_entry_and_sort_by_host() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let entry = |host: &str, source| BaselineEntry {
            host: host.into(),
            source,
            added_at: UNIX_EPOCH + Duration::from_secs(5),
        };
        block_on(s.add_to_baseline("work", &entry("z.example.com", EntrySource::Learned))).unwrap();
        block_on(s.add_to_baseline("work", &entry("a.example.com", EntrySource::Manual))).unwrap();
        block_on(s.add_to_baseline("work", &entry("z.example.com", EntrySource::Manual))).unwrap();
        let b = block_on(s.baseline("work")).unwrap();
        let got: Vec<_> = b
            .entries
            .iter()
            .map(|e| (e.host.as_str(), e.source))
            .collect();
        assert_eq!(
            got,
            [
                ("a.example.com", EntrySource::Manual),
                ("z.example.com", EntrySource::Learned)
            ]
        );
        assert_eq!(b.entries[0].added_at, UNIX_EPOCH + Duration::from_secs(5));
    }

    #[test]
    fn ip_links_and_module_state_use_the_clock() {
        let dir = tempfile::tempdir().unwrap();
        let clock = FakeClock::at_unix(1_700_000_000);
        let s = store(dir.path()).with_clock(Arc::new(clock.clone()));
        let id = block_on(s.upsert_host(&delta("api.example.com", 1))).unwrap();
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        block_on(s.link_ip(id, ip, Duration::from_secs(300))).unwrap();
        block_on(s.link_ip(id, ip, Duration::from_secs(60))).unwrap(); // never shortens
        block_on(s.put_module_state("url", "requests.api.example.com", &serde_json::json!(3)))
            .unwrap();

        let conn = rusqlite::Connection::open(s.path()).unwrap();
        let expires: i64 = conn
            .query_row(
                "SELECT expires_at FROM host_ips WHERE ip = '192.0.2.10'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(expires, 1_700_000_300_000);
        let updated: i64 = conn
            .query_row("SELECT updated_at FROM module_state", [], |r| r.get(0))
            .unwrap();
        assert_eq!(updated, 1_700_000_000_000);
    }

    #[test]
    fn state_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = store(dir.path());
            block_on(s.upsert_host(&delta("api.example.com", 1))).unwrap();
            block_on(s.put_module_state("url", "k", &serde_json::json!({"n": 1}))).unwrap();
        }
        let s = store(dir.path());
        assert_eq!(
            block_on(s.get_host("api.example.com"))
                .unwrap()
                .unwrap()
                .conn_count,
            1
        );
        assert_eq!(
            block_on(s.module_state("url")).unwrap()["k"],
            serde_json::json!({"n": 1})
        );
    }
}
