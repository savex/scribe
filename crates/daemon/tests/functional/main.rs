//! Functional tests of `scribe-daemon`: one behaviour at a time, through the crate's public interface.
//! Run with `cargo nextest run -p scribe-daemon -E 'binary(functional)'`.

mod app;
mod logging;
mod module_host;
mod modules;
mod scribed;
