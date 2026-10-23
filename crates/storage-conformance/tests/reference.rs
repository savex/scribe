//! Runs the suites against the in-memory reference backend to keep the suites themselves honest.

use scribe_storage_conformance::{block_on, event_sink_suite, state_store_suite};
use scribe_test_support::{MemorySink, MemoryStore};

#[test]
fn reference_state_store_conforms() {
    block_on(state_store_suite(&MemoryStore::default()));
}

#[test]
fn reference_event_sink_conforms() {
    block_on(event_sink_suite(&MemorySink::default()));
}
