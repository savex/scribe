//! Functional tests of `scribe-cli`: one behaviour at a time, through the crate's public interface.
//! Run with `cargo nextest run -p scribe-cli -E 'binary(functional)'`.

mod cli;
mod scribe;
