# scribe readiness by module

As of the end of **phase 1** (2026-11-22, commits `22d009f`…`29a5b88` plus the docs commit), scribe still
doesn't capture traffic or apply the modes, but it **stores**: the SQLite backend keeps hosts, counters,
baselines, alert and module state, and every kind of event, and passes both storage conformance suites.
`scribed` creates and migrates `state.db` and `events.db`; the released v1 and v2 snapshots migrate and
read back. Product code test coverage rose from 89% to 91.7%.

**How this was measured**
- **Completion** is an estimate against each module's scope in [plan.md](plan.md).
- **Coverage** is line coverage from `cargo test --workspace --all-features` alone, measured with LLVM
  source-based coverage (rustup `llvm-tools`) on macOS. 171 tests passed and 4 were skipped (Postgres
  conformance needs a database; sensor conformance needs privileges).
- Unit tests written inside source files (`#[cfg(test)]` modules) count as covered lines, which raises
  the percentages of `core`, `daemon` and `cli` somewhat. `crates/daemon/src/config/tests.rs` and
  `tests/` folders are excluded.
- Linux- and Windows-only code (memory lookup, journald) is compile-checked from macOS but only runs in CI.

## Phase 1 delivered (one commit per step)

| Step | Commit | Result |
|---|---|---|
| 1. Row codec | `22d009f` | `scribe_storage_api::codec`: one row layout (kind, module, host, schema, JSON payload) for SQLite and Postgres; schema 1 flows readable |
| 2. Connection, migrations | `9baf087` | `rusqlite` 0.43 bundled; WAL; migration runner with `schema_migrations` / `user_version`; newer schemas refused; health |
| 3. State store | `8f4d1a5` | Delta upserts, min / max seen times, sticky flags, IP links, baselines, alert and module state; state conformance passes |
| 4. Event sink | `29a5b88` | Transactional batches, `events` + `metrics`, merged time-ordered queries with totals; sink conformance passes; manager end to end |
| 5. Docs | this commit | Spec 0.9 (10.4 SQLite backend), skill, plan (98–123 days left), status, test approach, readme |

## Phase 0b delivered (one commit per step)

| Step | Commit | Result |
|---|---|---|
| 1. Module API | `a030cbb` | `scribe-module-api`: `Module`, `Manifest` checks, `FlowHook`, `Source`, `Emitter`, `ConfigDoc` (module config errors keep their line); notes, records and metric samples in `core` |
| 2. Flow events without URLs | `60026ad` | `FlowEvent.notes` replaces `url`, `FlowKind::Payload` replaces `Request`; sensors send `Observation`s with up to 4 KiB of client bytes; fixtures regenerated |
| 3. Storage interface | `1b93348` | `EventKind::Metric` / `Module`, `StoredEvent::Metric` / `Module`, module state in `StateStore`; conformance and routing tests |
| 4. Schema v2 | `3273dbc` | Migration `0002_modules.sql` (SQLite, Postgres), snapshots `v2.db` / `v2_seed.sql`; v1 snapshot unchanged |
| 5. Module conformance | `99019a5` | `scribe-module-conformance`; test modules for hooks and sources; 7 injected faults caught |
| 6. URL module | `96ba5d3` | `scribe-module-url`: manifest, `[modules.url] query`, deprecated `privacy.url_query` honoured, hook and counters; parser stub and fuzz target moved here |
| 7. Config | `d14435b` | `[modules]` with per-module sections checked by the module; sink events accept module kinds; deprecation warning; `--check-config` shows module settings |
| 8. Daemon | `24d948a` | `ModuleHost`: hook budget, panic isolation, source schedules, pause / resume / reconfigure / stop, bounded output queue to storage |
| 9. Docs and CI | this commit | Spec 0.8 (7.4.9 lists five refinements), skill §9b, `CLAUDE.md` module rule, readme, test approach, plan, status; release smoke test checks the URL module |

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
| `core` | 0, 0b | **~95%** | Flow event with module notes, `Observation`, modes, sensor interface, clock, alert interface, module data types, `VERSION`, units, platform defaults | Grows as later phases need shared types | **97%** (455/471) |
| `module-api` | 0b | **~95%** | `Module`, `Manifest` checks, `FlowHook`, `Source`, `Emitter`, `ModuleContext`, `ConfigDoc`, `Signal`, `Reload` | API service hooks (phase 10), `ProbeHost` (native sensors) | **99%** (303/307) |
| `module-url` | 0b, 3, 10 | **~35%** | Manifest, `[modules.url] query` with the deprecated alias, flow hook, request counters; passes the module suite | Request parser and URL privacy rules (phase 3), `scribe url` (phase 10) | **86%** (139/161) |
| `storage-api` | 0b, 1–2 | **~95%** | Interfaces with module records, metric samples and module state, `EventKind` names, schema version 2, shared row codec | Grows with phase 2 (health details, retention calls) | **94%** (469/501) |
| `storage-manager` | 2 | **~20%** | Registry, routing by kind (module kinds too), per-sink retention and batching settings | Host cache, state-store outage buffer, per-sink batching tasks, spool and replay, retention, health | **100%** (110/110) |
| `storage-sqlite` | 1 | **100%** | Migration runner, every state store and event sink method, WAL, health; passes both conformance suites; reads both snapshots | Retention deletes come with the manager (phase 2) | **93%** (540/580) |
| `storage-postgres` | 12 | **~15%** | v1 and v2 migrations and seeds, factory, stubs | All of it | **3%** (3/112). Conformance tests skipped. |
| `enrich` | 3 | **~10%** | TLS / plaintext detection, DNS cache, `Host` header stub; `ring` chosen for QUIC | SNI, `Host`, DNS answers, QUIC | **38%** (16/42) |
| Policy engine (`crates/policy`) | 4 | **0% code, design done** | Location, scores, threshold, ports and entropy rule decided; module signals defined | All code | n/a |
| `daemon` (`scribed`) | 0, 0b, 5 | **~32%** | Config loading and checks (modules included), logging, startup summary, folders, SQLite storage created and migrated, `ModuleHost`, module output queue stored, signal handling, exit codes | Sensor → enrichment → modules → policy → storage pipeline, run states, service-manager integration, dropping privileges | **95%** (1510/1582) |
| `sensor-pcap` | 6 | **~2%** | Stub (sends `Observation`s) | Capture and flow reassembly | **60%** (6/10), stub only |
| `sensor-linux` (eBPF) | 7 | **~2%** | Stub, Linux only | eBPF programs, loader, process lookup | n/a (not built on macOS) |
| `sensor-windows` (ETW) | 8 | **~2%** | Stub, Windows only | ETW session, DNS-client events, Npcap | n/a (not built on macOS) |
| macOS Network Extension | 9 | **0%** | README only | Swift extension, XPC bridge | n/a |
| Local API (`crates/api`) and `cli` | 10 | **~20%** | CLI parses every command with `clap`, exit codes; API location decided | gRPC API, `scribe daemon` and `scribe modules`; commands talk to nothing | **96%** (92/96) |
| Alert outputs (`crates/alerts`) | 11 | **~5%** | Alert output interface | Notifications, log, webhook | n/a |
| UI (Tauri) | later | **0%** | Test folders and mock API data | Everything | n/a |
| Packaging | 13 | **~15%** | Release archives with checksums; release smoke test runs both binaries and checks the shipped config and the URL module | `.deb` / `.rpm`, MSI, notarized `.pkg`, signing | n/a |

**Product total:** 3,643 of 3,972 measurable lines covered (**91.7%**), up from 89% after phase 0b.
The coverage targets in the test approach (≥ 80% for `core` and the daemon config) are met.

## Test infrastructure, CI and data

| Module | Completion | What exists | Test coverage |
|---|---|---|---|
| `test-support` | **100%** | Test doubles (with module doubles and `RecordingEmitter`), packet builders, pcap writer, fixture generator | **90%** (1227/1359) |
| `storage-conformance` | **100%** | Suite every storage backend must pass, with module data | **98%** (311/319) |
| `sensor-conformance` | **100%** | Suite every sensor must pass (checks client bytes), plus the traffic generator | **41%** (86/210); the runner needs a real sensor |
| `module-conformance` | **100%** | Suite every module must pass | **85%** (236/279) |
| Test data | **100%** | 13 pcap fixtures (expecting `notes.url`), 11 scenarios, raw sensor samples, v1 and v2 database snapshots | Checked by the fixture and snapshot tests |
| Fuzzing | **~30%** | 2 targets with seeds (`http_request` now targets the URL module) | Never run (needs Rust nightly) |
| End-to-end scripts | **100% scripted** | Linux, macOS, Windows | Never run (needs installers and CLI commands) |
| CI and versioning | **~90%** | 8 workflows; minimum-version job; release smoke test covers `scribed` and the URL module; Postgres job loads migration 0002 | Run locally only, not on GitHub |

**Overall:** 5,503 of 6,139 measurable lines covered (**89.6%**).

## What this means

- **Phases 0, 0b and 1 are done.** Remaining effort: 98–123 days (118–148 with buffer); milestone M1: 44–54 days.
- **The daemon has a skeleton to grow into:** each next phase plugs into `serve()` (storage manager tasks in
  phase 2, the pipeline in phase 5, which feeds `ModuleHost::on_flow`) and reads its settings from the already-checked config.
- **Next steps** (plan milestone M1):
  1. Phase 2: the storage manager (per-sink tasks and batching, host cache, outage buffer, spool, retention).
  2. Phase 3: SNI, `Host` and DNS parsers against the 13 pcap fixtures, the URL module's HTTP parser (with URL redaction), then QUIC with `ring`.
  3. Phase 4: the policy engine in `crates/policy`, against the 11 scenarios, using the config values.
  4. Apply for Apple's Network Extension entitlement (plan risk 1).
- **Not verified here:** the Linux and Windows code paths at run time, the GitHub workflows themselves,
  the Postgres migration 0002 (no local Postgres; the Tests workflow loads it) and the fuzz targets (no nightly).
  Local Linux / Windows compile checks leave out bundled SQLite (it needs a C cross compiler); CI builds it natively.
