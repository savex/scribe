//! Functional tests of `scribe-core`: one behaviour at a time, through the crate's public interface.
//! Run with `cargo nextest run -p scribe-core -E 'binary(functional)'`.

mod event;
mod module;
mod sensor;
