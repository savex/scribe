//! Scenario tests: one test per file in `testdata/scenarios/`, played through the whole pipeline
//! in-process (`FakeSensor`, `FakeClock`, temporary SQLite, `RecordingAlertSink`).
//!
//! The scenario runner arrives with the policy engine (plan phase 4); until then this binary has no
//! tests. Run with `cargo nextest run -E 'binary(scenario)'`.
