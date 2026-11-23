//! Shared test helpers. Never a dependency of production crates, only `[dev-dependencies]`.
//!
//! - [`clock`] — `FakeClock`
//! - [`sensor`] — `FakeSensor` and the `flow()` event builder
//! - [`storage`] — `MemoryStore`, `MemorySink`, `FaultySink`
//! - [`alerts`] — `RecordingAlertSink`
//! - [`modules`] — `RecordingEmitter`, `TagModule` (flow hook), `TicksModule` (source), `NoopModule`,
//!   `MisbehavingModule`
//! - [`packets`] — Ethernet/IP/TCP/UDP, TLS, DNS and HTTP builders plus a pcap writer
//! - [`fixtures`] — the pcap fixtures in `testdata/pcap/` and fuzz seeds, built from code
//!
//! Regenerate fixtures with `cargo run -p scribe-test-support --bin gen-fixtures`.

pub mod alerts;
pub mod clock;
pub mod fixtures;
#[cfg(feature = "mock-api")]
pub mod mock_api;
pub mod modules;
pub mod packets;
pub mod sensor;
pub mod storage;

pub use alerts::RecordingAlertSink;
pub use clock::FakeClock;
#[cfg(feature = "mock-api")]
pub use mock_api::{MockApiServer, Scenario};
pub use modules::{
    module_context, Fault, MisbehavingModule, NoopModule, RecordingEmitter, TagModule, TicksModule,
};
pub use sensor::{flow, FakeSensor, FlowBuilder};
pub use storage::{FaultySink, MemorySink, MemoryStore};

use std::path::PathBuf;

/// Repository root, for locating `testdata/` and `fuzz/`.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `testdata/<relative>` under the repository root.
pub fn testdata(relative: &str) -> PathBuf {
    repo_root().join("testdata").join(relative)
}
