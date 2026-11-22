use std::collections::HashMap;
use std::path::Path;

use scribe_storage_conformance::{block_on, event_sink_suite, state_store_suite};
use scribe_storage_sqlite::{SqliteSink, SqliteStore};

fn options(dir: &Path, file: &str) -> HashMap<String, String> {
    let path = dir.join(file).to_string_lossy().into_owned();
    HashMap::from([("path".to_owned(), path)])
}

#[test]
fn sqlite_state_store_conforms() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::from_options(&options(dir.path(), "state.db")).unwrap();
    block_on(state_store_suite(&store));
}

#[test]
#[ignore = "sqlite event sink lands in the next step"]
fn sqlite_event_sink_conforms() {
    let dir = tempfile::tempdir().unwrap();
    let sink = SqliteSink::from_options("test", &options(dir.path(), "events.db")).unwrap();
    block_on(event_sink_suite(&sink));
}

#[test]
fn state_and_sink_can_share_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::from_options(&options(dir.path(), "scribe.db")).unwrap();
    let sink = SqliteSink::from_options("local", &options(dir.path(), "scribe.db")).unwrap();
    block_on(scribe_storage_api::StateStore::migrate(&store)).unwrap();
    block_on(scribe_storage_api::EventSink::migrate(&sink)).unwrap();
    assert_eq!(
        store.schema_version().unwrap(),
        sink.schema_version().unwrap()
    );
}
