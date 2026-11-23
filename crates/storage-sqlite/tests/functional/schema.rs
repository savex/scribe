//! The migration runner on new files, on the released snapshots and on files from the future.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use scribe_storage_api::{Health, StateStore, StorageError, SCHEMA_VERSION};
use scribe_storage_conformance::block_on;
use scribe_storage_sqlite::SqliteStore;

fn store(path: &Path) -> SqliteStore {
    let options = HashMap::from([("path".to_owned(), path.to_string_lossy().into_owned())]);
    SqliteStore::from_options(&options).unwrap()
}

fn snapshot(version: u32, dir: &Path) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../testdata/db/sqlite/v{version}.db"));
    let dst = dir.join(format!("v{version}.db"));
    std::fs::copy(src, &dst).unwrap();
    dst
}

fn rusqlite_open(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}

#[test]
fn a_new_file_gets_every_migration() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir.path().join("state.db"));
    assert_eq!(s.schema_version().unwrap(), 0);
    assert!(matches!(block_on(s.health()), Health::Degraded(_)));
    block_on(s.migrate()).unwrap();
    assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    block_on(s.migrate()).unwrap();
    assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    assert_eq!(block_on(s.health()), Health::Ok);
}

#[test]
fn refuses_a_database_from_a_newer_scribed() {
    let dir = tempfile::tempdir().unwrap();
    let path = snapshot(SCHEMA_VERSION, dir.path());
    let conn = rusqlite_open(&path);
    conn.execute(
        "INSERT INTO schema_migrations (version, applied_at) VALUES (99, 0)",
        [],
    )
    .unwrap();
    drop(conn);
    let err = block_on(store(&path).migrate()).unwrap_err();
    assert!(matches!(err, StorageError::Data(_)), "{err}");
    assert!(
        err.to_string()
            .contains("schema version 99, newer than this scribed reads"),
        "{err}"
    );
}

#[test]
fn an_unopenable_path_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&dir.path().join("missing-dir").join("state.db"));
    let err = block_on(s.migrate()).unwrap_err();
    assert!(err.to_string().contains("cannot open"), "{err}");
    assert!(matches!(block_on(s.health()), Health::Down(_)));
}

#[test]
fn v2_migrates_to_v3_and_flags_ip_hosts() {
    use scribe_storage_api::StateStore;
    let dir = tempfile::tempdir().unwrap();
    let s = store(&snapshot(2, dir.path()));
    block_on(s.migrate()).unwrap();
    let ip = block_on(s.get_host("198.51.100.7")).unwrap().unwrap();
    assert!(
        ip.unresolved,
        "IP hosts stored before v3 count as unresolved"
    );
    let named = block_on(s.get_host("api.example.com")).unwrap().unwrap();
    assert!(!named.unresolved);
    assert!(block_on(s.process_hosts(None)).unwrap().is_empty());
}

#[test]
fn the_v3_snapshot_reads_back() {
    use scribe_storage_api::StateStore;
    let dir = tempfile::tempdir().unwrap();
    let s = store(&snapshot(3, dir.path()));
    block_on(s.migrate()).unwrap();
    let ech = block_on(s.get_host("public.example.com")).unwrap().unwrap();
    assert!(ech.unresolved);
    let curl = block_on(s.process_hosts(Some("/usr/bin/curl"))).unwrap();
    let hosts: Vec<_> = curl
        .iter()
        .map(|r| (r.host.as_str(), r.conn_count, r.bytes_out))
        .collect();
    assert_eq!(
        hosts,
        [("plain.example.com", 1, 96), ("public.example.com", 1, 512)]
    );
}

#[test]
fn v3_migrates_to_v4_with_empty_hourly_buckets() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(&snapshot(3, dir.path()));
    block_on(s.migrate()).unwrap();
    assert_eq!(s.schema_version().unwrap(), 4);
    let hours = block_on(s.host_hours("api.example.com", std::time::UNIX_EPOCH)).unwrap();
    assert!(hours.is_empty(), "hours before v4 were never counted");
}

#[test]
fn the_v4_snapshot_reads_back() {
    use std::time::{Duration, UNIX_EPOCH};
    let dir = tempfile::tempdir().unwrap();
    let s = store(&snapshot(4, dir.path()));
    block_on(s.migrate()).unwrap();
    let hours = block_on(s.host_hours("api.example.com", UNIX_EPOCH)).unwrap();
    let rows: Vec<_> = hours
        .iter()
        .map(|b| (b.hour, b.conn_count, b.bytes_out))
        .collect();
    assert_eq!(
        rows,
        [
            (
                UNIX_EPOCH + Duration::from_millis(1_700_298_000_000),
                3,
                1536
            ),
            (
                UNIX_EPOCH + Duration::from_millis(1_700_301_600_000),
                1,
                512
            )
        ]
    );
}
