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
