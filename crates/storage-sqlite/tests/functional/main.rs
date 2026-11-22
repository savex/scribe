//! Functional tests of `scribe-storage-sqlite`: one behaviour at a time, through the crate's public interface.
//! Run with `cargo nextest run -p scribe-storage-sqlite -E 'binary(functional)'`.

mod conformance;
mod counters;
mod schema;
mod sink;
mod state;
