//! Needs a disposable database: `SCRIBE_TEST_POSTGRES_URL=postgres://user@localhost/scribe_test`.

use std::collections::HashMap;

use scribe_storage_conformance::{block_on, event_sink_suite, state_store_suite};
use scribe_storage_postgres::{PostgresSink, PostgresStore};

fn options() -> Option<HashMap<String, String>> {
    let url = std::env::var("SCRIBE_TEST_POSTGRES_URL").ok()?;
    Some(HashMap::from([("url".to_owned(), url)]))
}

mod functional {
    use super::*;

    #[test]
    #[ignore = "postgres backend not implemented yet; needs SCRIBE_TEST_POSTGRES_URL"]
    fn postgres_state_store_conforms() {
        let Some(opts) = options() else { return };
        let store = PostgresStore::from_options(&opts).unwrap();
        block_on(state_store_suite(&store));
    }

    #[test]
    #[ignore = "postgres backend not implemented yet; needs SCRIBE_TEST_POSTGRES_URL"]
    fn postgres_event_sink_conforms() {
        let Some(opts) = options() else { return };
        let sink = PostgresSink::from_options("test", &opts).unwrap();
        block_on(event_sink_suite(&sink));
    }
}
