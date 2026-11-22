//! Counter properties (random update sequences) and concurrent writers.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use proptest::prelude::*;
use scribe_core::Security;
use scribe_storage_api::{HostDelta, StateStore};
use scribe_storage_conformance::block_on;
use scribe_storage_sqlite::SqliteStore;

fn store_at(path: &Path) -> SqliteStore {
    let options = HashMap::from([("path".to_owned(), path.to_string_lossy().into_owned())]);
    let s = SqliteStore::from_options(&options).unwrap();
    block_on(s.migrate()).unwrap();
    s
}

fn security() -> impl Strategy<Value = Security> {
    prop_oneof![
        Just(Security::Tls),
        Just(Security::Quic),
        Just(Security::Plaintext),
        Just(Security::Unknown),
    ]
}

fn update() -> impl Strategy<Value = (usize, u64, u64, u64, u64, Security)> {
    (
        0..3usize,
        0..1_000u64,
        0..5u64,
        0..5u64,
        0..100_000u64,
        security(),
    )
}

#[derive(Default, Debug, PartialEq)]
struct Expected {
    conn: u64,
    req: u64,
    bytes: u64,
    first: u64,
    last: u64,
    tls: bool,
    plain: bool,
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Stored counters equal the sums of the deltas; first / last seen are min / max; flags only
    /// turn on.
    #[test]
    fn counters_are_sums(updates in prop::collection::vec(update(), 1..40)) {
        let dir = tempfile::tempdir().unwrap();
        let s = store_at(&dir.path().join("state.db"));
        let names = ["a.example.com", "b.example.com", "c.example.com"];
        let mut want: BTreeMap<&str, Expected> = BTreeMap::new();
        for (h, at, conn, req, bytes, sec) in updates {
            let name = names[h];
            block_on(s.upsert_host(&HostDelta {
                name: name.into(),
                seen_at: UNIX_EPOCH + Duration::from_secs(at),
                connections: conn,
                requests: req,
                bytes_out: bytes,
                security: sec,
            }))
            .unwrap();
            let e = want.entry(name).or_insert(Expected { first: at, last: at, ..Default::default() });
            e.conn += conn;
            e.req += req;
            e.bytes += bytes;
            e.first = e.first.min(at);
            e.last = e.last.max(at);
            e.tls |= sec == Security::Tls;
            e.plain |= sec == Security::Plaintext;
        }
        for (name, e) in want {
            let h = block_on(s.get_host(name)).unwrap().unwrap();
            let got = Expected {
                conn: h.conn_count,
                req: h.req_count,
                bytes: h.bytes_out,
                first: h.first_seen.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                last: h.last_seen.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                tls: h.tls_seen,
                plain: h.plaintext_seen,
            };
            prop_assert_eq!(got, e, "{}", name);
        }
    }
}

#[test]
fn many_writers_on_one_file_lose_nothing() {
    // Four threads, each with its own store (connection) on the same file, update one host.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    store_at(&path);
    let writers: Vec<_> = (0..4)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || {
                let s = store_at(&path);
                for i in 0..100 {
                    block_on(s.upsert_host(&HostDelta {
                        name: "api.example.com".into(),
                        seen_at: UNIX_EPOCH + Duration::from_secs(i),
                        connections: 1,
                        requests: 0,
                        bytes_out: 10,
                        security: Security::Tls,
                    }))
                    .unwrap();
                }
            })
        })
        .collect();
    for w in writers {
        w.join().unwrap();
    }
    let h = block_on(store_at(&path).get_host("api.example.com"))
        .unwrap()
        .unwrap();
    assert_eq!((h.conn_count, h.bytes_out), (400, 4_000));
}
