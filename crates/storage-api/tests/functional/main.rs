//! Functional tests of `scribe-storage-api`: one behaviour at a time, through the crate's public interface.
//! Run with `cargo nextest run -p scribe-storage-api -E 'binary(functional)'`.

mod codec;
mod error;
mod model;
