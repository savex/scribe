//! Integration tests: data passing from one crate to another.
//! Run with `cargo nextest run -E 'binary(integration)'`.

#[cfg(unix)]
mod api;
mod daemon;
mod enrich;
mod storage;
