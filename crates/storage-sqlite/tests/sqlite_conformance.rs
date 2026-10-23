use std::collections::HashMap;

use scribe_storage_conformance::{block_on, event_sink_suite, state_store_suite};
use scribe_storage_sqlite::{SqliteSink, SqliteStore};

fn options(dir: &std::path::Path, file: &str) -> HashMap<String, String> {
    let path = dir.join(file).to_string_lossy().into_owned();
    HashMap::from([("path".to_owned(), path)])
}

#[test]
#[ignore = "sqlite backend not implemented yet"]
fn sqlite_state_store_conforms() {
    let dir = std::env::temp_dir().join("scribe-sqlite-conformance");
    std::fs::create_dir_all(&dir).unwrap();
    let store = SqliteStore::from_options(&options(&dir, "state.db")).unwrap();
    block_on(state_store_suite(&store));
}

#[test]
#[ignore = "sqlite backend not implemented yet"]
fn sqlite_event_sink_conforms() {
    let dir = std::env::temp_dir().join("scribe-sqlite-conformance");
    std::fs::create_dir_all(&dir).unwrap();
    let sink = SqliteSink::from_options("test", &options(&dir, "events.db")).unwrap();
    block_on(event_sink_suite(&sink));
}
