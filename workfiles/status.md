# scribe readiness by module

As of the end of **phase 0** (2026-11-08, commits `5e521e9`…`dcb99ea` plus the docs commit), scribe is
still not usable for monitoring: it doesn't capture traffic, store anything, or apply the modes.
What changed: `scribed` is now a real long-running process. It finds, checks and resolves the full v1
config, logs to a file or the system log, opens storage through the registry, and stops cleanly on
Ctrl-C or SIGTERM. The `scribe` CLI parses every command. Product code test coverage rose from 5% to 86%.

**How this was measured**
- **Completion** is an estimate against each module's scope in [plan.md](plan.md).
- **Coverage** is line coverage from `cargo test --workspace --all-features` alone, measured with LLVM
  source-based coverage (rustup `llvm-tools`) on macOS. 100 tests passed and 6 were skipped.
- Unit tests written inside source files (`#[cfg(test)]` modules) count as covered lines, which raises
  the percentages of `core`, `daemon` and `cli` somewhat. `crates/daemon/src/config/tests.rs` and
  `tests/` folders are excluded.
- Linux- and Windows-only code (memory lookup, journald) is compile-checked from macOS but only runs in CI.

## Phase 0 delivered (one commit per step)

| Step | Commit | Result |
|---|---|---|
| Changelog | `5e521e9` | [changelog.md](../changelog.md), Keep a Changelog format; `CLAUDE.md` requires an entry per relevant commit |
| 1. Dependencies, error types | `f8862ff` | Workspace dependencies for Rust 1.89; `StorageError` / `SensorError` on `thiserror` |
| 2. Units | `96c046e` | Durations, sizes and percentages with clear errors and property tests |
| 3. Platform | `ced1cfa` | Default paths per OS, total RAM, volume size |
| 4. Config | `534f254` | Full v1 model, errors with line and column, cross-field checks, resolution, `config/scribe.toml` = defaults |
| 5. Logging | `74976d2` | Level / `SCRIBE_LOG`, text / JSON, daily or size rotation, journald / unified logging, stderr fallback |
| 6. Daemon | `adb5b75` | `--config`, `--check-config`, `--version`; startup summary; Ctrl-C / SIGTERM shutdown; exit codes 0 / 1 / 2 |
| 7. CLI | `6b36d08` | All commands on `clap`; `version` works, others report "not implemented yet" |
| 8. Storage manager tests | `dcb99ea` | Registry and routing tests |
| 9. Docs and CI | this commit | Release workflow also checks `scribed --version` and the shipped config; readme, spec, skill, plan, status |

**Also fixed:** `specs.md` §9.2 *Environment variables* and §9.3 *Build options* had been deleted by an
earlier edit (`111411c`); they are restored.

## Product modules

| Module | Plan phase | Completion | What exists | What's missing | Test coverage |
|---|---|---|---|---|---|
| `core` | 0 | **~95%** | Flow event, modes (with serde), sensor interface, clock, alert interface, `VERSION`, units, platform defaults | Grows as later phases need shared types | **95%** (386/405) |
| `storage-api` | 1–2 | **~85%** | Interfaces, data model, capability flags, errors (`thiserror`) | Payload serialization (serde), schema version on records | **77%** (37/48) |
| `storage-manager` | 2 | **~20%** | Registry, routing to sinks, per-sink retention and batching settings; fully tested | Host cache, state-store outage buffer, per-sink batching tasks, spool and replay, retention, health | **100%** (110/110) |
| `storage-sqlite` | 1 | **~10%** | v1 schema, factory, option checks; methods are stubs | All of it (rusqlite, migration runner, queries) | **32%** (32/99), factory paths only. Conformance tests skipped. |
| `storage-postgres` | 12 | **~10%** | v1 schema, factory, stubs | All of it | **3%** (3/101). Conformance tests skipped. |
| `enrich` | 3 | **~10%** | TLS / plaintext detection, DNS cache; `ring` chosen for QUIC | SNI, HTTP with URL redaction, DNS answers, QUIC | **38%** (16/42) |
| Policy engine (`crates/policy`) | 4 | **0% code, design done** | Location, scores, threshold, ports and entropy rule decided; config loads and checks them | All code | n/a |
| `daemon` (`scribed`) | 0, 5 | **~25%** | Config loading and checks, logging, startup summary, folders, storage setup, signal handling, exit codes | Sensor → enrichment → policy → storage pipeline, service-manager integration, dropping privileges | **96%** (1028/1065) |
| `sensor-pcap` | 6 | **~2%** | Stub | Capture and flow reassembly | **60%** (6/10), stub only |
| `sensor-linux` (eBPF) | 7 | **~2%** | Stub, Linux only | eBPF programs, loader, process lookup | n/a (not built on macOS) |
| `sensor-windows` (ETW) | 8 | **~2%** | Stub, Windows only | ETW session, DNS-client events, Npcap | n/a (not built on macOS) |
| macOS Network Extension | 9 | **0%** | README only | Swift extension, XPC bridge | n/a |
| Local API (`crates/api`) and `cli` | 10 | **~20%** | CLI parses every command with `clap`, exit codes; API location decided | gRPC API; commands talk to nothing | **96%** (92/96) |
| Alert outputs (`crates/alerts`) | 11 | **~5%** | Alert output interface | Notifications, log, webhook | n/a |
| UI (Tauri) | later | **0%** | Test folders and mock API data | Everything | n/a |
| Packaging | 13 | **~15%** | Release archives with checksums; release smoke test runs both binaries and checks the shipped config | `.deb` / `.rpm`, MSI, notarized `.pkg`, signing | n/a |

**Product total:** 1,710 of 1,976 measurable lines covered (**86.5%**), up from 25 of 468 (5.3%).
The coverage targets in the test approach (≥ 80% for `core` and the daemon config) are met.

## Test infrastructure, CI and data

| Module | Completion | What exists | Test coverage |
|---|---|---|---|
| `test-support` | **100%** | Test doubles, packet builders, pcap writer, fixture generator | **85%** (868/1019) |
| `storage-conformance` | **100%** | Suite every storage backend must pass | **98%** (215/220) |
| `sensor-conformance` | **100%** | Suite every sensor must pass, plus the traffic generator | **48%** (89/187); the runner needs a real sensor |
| Test data | **100%** | 13 pcap fixtures, 11 scenarios, raw sensor samples, v1 database snapshots | Checked by the fixture test |
| Fuzzing | **~30%** | 2 targets with seeds | Never run (needs Rust nightly) |
| End-to-end scripts | **100% scripted** | Linux, macOS, Windows | Never run (needs installers and CLI commands) |
| CI and versioning | **~90%** | 8 workflows; minimum-version job from `Cargo.toml`; release smoke test now covers `scribed` | Run locally only, not on GitHub |

**Overall:** 2,882 of 3,402 measurable lines covered (**85%**).

## What this means

- **Phase 0 is done.** Remaining effort: 85–111.5 days (102–134 with buffer); milestone M1: 40.5–52 days, including the `scribe daemon` subcommands added to phases 5 and 10.
- **The daemon has a skeleton to grow into:** each next phase plugs into `serve()` (storage in phase 1, the
  pipeline in phase 5) and reads its settings from the already-checked config.
- **Next steps** (plan milestone M1):
  1. Phase 1: the SQLite backend, against its waiting conformance tests.
  2. Phase 3: SNI, HTTP (with URL redaction) and DNS parsers against the 13 pcap fixtures, then QUIC with `ring`.
  3. Phase 4: the policy engine in `crates/policy`, against the 11 scenarios, using the config values.
  4. Apply for Apple's Network Extension entitlement (plan risk 1).
- **Not verified here:** the Linux and Windows code paths at run time, and the GitHub workflows themselves.
