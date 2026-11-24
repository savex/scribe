//! Integration tests: data passing from one crate to another.
//! Run with `cargo nextest run -E 'binary(integration)'`.

#[cfg(unix)]
mod alerts;
#[cfg(unix)]
mod api;
#[cfg(unix)]
mod cli;
mod daemon;
mod enrich;
mod storage;
