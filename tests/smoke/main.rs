//! Smoke tests: critical paths only. They change nothing outside their own temporary folder.
//! Run with `cargo nextest run -E 'binary(smoke)'`.

mod binaries;
mod config;
mod fixtures;
mod pcap;
mod schema;
mod storage;
