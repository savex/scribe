//! Functional tests of `scribe-module-url`: one behaviour at a time, through the crate's public interface.
//! Run with `cargo nextest run -p scribe-module-url -E 'binary(functional)'`.

mod conformance;
mod hook;
mod privacy;
mod url;
