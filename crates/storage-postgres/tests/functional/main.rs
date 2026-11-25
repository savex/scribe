//! Functional tests of `scribe-storage-postgres`: one behaviour at a time, through the crate's public interface.
//! Run with `cargo nextest run -p scribe-storage-postgres -E 'binary(functional)'`.

mod conformance;
mod settings;
