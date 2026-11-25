//! The storage conformance suites against a real database: set
//! `SCRIBE_TEST_POSTGRES_URL=postgres://user:password@localhost/scribe_test` (the Tests workflow's
//! Postgres job does). Without it the sink test returns at once. Each run uses its own schema, so
//! earlier runs' rows never count; the database is meant to be thrown away.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use scribe_storage_conformance::{block_on, event_sink_suite, state_store_suite};
use scribe_storage_postgres::{PostgresSink, PostgresStore};

fn options() -> Option<HashMap<String, String>> {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let url = std::env::var("SCRIBE_TEST_POSTGRES_URL").ok()?;
    let schema = format!(
        "scribe_test_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    Some(HashMap::from([
        ("url".to_owned(), url),
        ("schema".to_owned(), schema),
    ]))
}

#[test]
#[ignore = "the postgres state store is not implemented yet (phase 12 after the sink)"]
fn postgres_state_store_conforms() {
    let Some(opts) = options() else { return };
    let store = PostgresStore::from_options(&opts).unwrap();
    block_on(state_store_suite(&store));
}

#[test]
fn postgres_event_sink_conforms() {
    let Some(opts) = options() else { return };
    let sink = PostgresSink::from_options("test", &opts).unwrap();
    block_on(event_sink_suite(&sink));
    // A second sink on the same schema finds it migrated already.
    let again = PostgresSink::from_options("again", &opts).unwrap();
    block_on(scribe_storage_api::EventSink::migrate(&again)).unwrap();
    assert!(matches!(
        block_on(scribe_storage_api::EventSink::health(&again)),
        scribe_storage_api::Health::Ok
    ));
}
