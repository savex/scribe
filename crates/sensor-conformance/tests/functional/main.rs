//! Functional tests of `scribe-sensor-conformance`: one behaviour at a time, through the crate's public interface.
//! Run with `cargo nextest run -p scribe-sensor-conformance -E 'binary(functional)'`.

mod sensors;
mod traffic_generator;
