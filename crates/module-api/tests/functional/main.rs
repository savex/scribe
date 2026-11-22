//! Functional tests of `scribe-module-api`: one behaviour at a time, through the crate's public interface.
//! Run with `cargo nextest run -p scribe-module-api -E 'binary(functional)'`.

mod config;
mod hooks;
mod manifest;
