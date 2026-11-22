# scribe readiness by module

As of the end of **phase 3** (2026-11-22, commits `5a2ce1b`…`568ccb9` plus the docs commit), scribe still
doesn't capture traffic or apply the modes, but **everything between a sensor and the modules is ready**:
the `Enricher` names flows from TLS SNI, the HTTP `Host` header, DNS answers and QUIC Initial packets,
classifies security and flags ECH; the URL module parses requests and applies all five `query` modes,
including `hash` with a key from the new `scribe-secrets` crate. Every one of the 16 pcap fixtures gives its
expected flows end to end. Product code coverage is 91.7%.

**How this was measured**
- **Completion** is an estimate against each module's scope in [plan.md](plan.md).
- **Coverage** is line coverage from `cargo test --workspace --all-features` alone, measured with LLVM
  source-based coverage (rustup `llvm-tools`) on macOS, all rows re-measured after phase 3. 270 tests
  passed and 4 were skipped (Postgres
  conformance needs a database; sensor conformance needs privileges).
- Unit tests written inside source files (`#[cfg(test)]` modules) count as covered lines, which raises
  the percentages of `core`, `daemon` and `cli` somewhat. `crates/daemon/src/config/tests.rs` and
  `tests/` folders are excluded.
- Linux- and Windows-only code (memory lookup, journald) is compile-checked from macOS but only runs in CI.

## Phase 3 delivered (one commit per step)

| Step | Commit | Result |
|---|---|---|
| 1. TLS ClientHello | `5a2ce1b` | SNI (checked, lower case), ALPN, ECH, TLS 1.3 offer; hellos split across records; never panics |
| 2. HTTP and URL privacy | `f204aa7` | Request heads and `Host` (origin, proxy, CONNECT forms) in `enrich`; URL parser and the specs 12.2 rules in `module-url` |
| 3. DNS | `2998eaa` | Response parser (compression with a jump limit, A / AAAA / CNAME) and an IP-to-name cache on `Clock` |
| 4. Enricher | `a3e0840` | Name order SNI > `Host` > sensor name > DNS cache, security, ECH flag; DNS integration test |
| 5. Secrets and URL hash | `b498a56` | `scribe-secrets` (`file:` with owner and mode checks, race-safe key creation; OS stores parsed, in phase 11); `query = "hash"` with HMAC-SHA256; `ModuleContext::data_dir` |
| 6. QUIC | `c11fc71` | Initial decryption with `ring` (v1, v2), CRYPTO reassembly across packets; RFC 9001 / 9369 sample packets; 2 new fixtures |
| 7. Fuzzing | `568ccb9` | `dns_message` and `quic_initial` targets with seeds; seeds tested against the parsers |
| 8. Docs | this commit | Every fixture end to end (INT-18), UDP classification; spec, skill, plan, status, test list, test approach, diagram, changelog |

## Phase 2 delivered (one commit per step)

| Step | Commit | Result |
|---|---|---|
| 1. Retention call | `6122243` | `EventSink::delete_before`; SQLite and doubles; conformance case |
| 2. SQLite worker | `d8e4447` | A worker thread per database; `Reply` futures work on any executor |
| 3. Writer tasks | `d04aa80` | `Storage`: writer per sink, batching by size and time, non-blocking `publish`, retention, counters, shutdown |
| 4. Spool | `fa298ce` | On-disk spool, ordered replay with back-off, shared size and free-disk limits, replay after restart |
| 5. Outage buffer | `59ae1da` | `BufferedState`: ordered buffer within limits, replay, links by name, `Data` errors not buffered |
| 6. Cache and health | `3dbfade` | LRU host cache and baseline cache; `Storage::health` |
| 7. Missing tests | `d24cfef` | In-memory SQLite suites, counter property test, concurrent writers, running-storage integration test |
| 8. Docs | this commit | Spec 0.10 (10.5), skill, plan, status, test list, test approach, changelog |

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
| `core` | 0, 0b | **~95%** | Flow event with module notes, `Observation`, modes, sensor interface, clock, alert interface, module data types, `VERSION`, units, platform defaults | Grows as later phases need shared types | **97%** (419/432) |
| `module-api` | 0b | **~95%** | `Module`, `Manifest` checks, `FlowHook`, `Source`, `Emitter`, `ModuleContext` (with `data_dir`), `ConfigDoc`, `Signal`, `Reload` | API service hooks (phase 10), `ProbeHost` (native sensors) | **98%** (156/160) |
| `module-url` | 0b, 3, 10 | **~80%** | Manifest, `[modules.url] query` and `hash_key`, request parser, all five `query` modes, flow hook, request counters; passes the module suite and every HTTP fixture | `scribe url` (phase 10) | **97%** (233/240) |
| `storage-api` | 0b, 1–2 | **100%** | Interfaces with module data, `EventKind`, schema version 2, row codec, `delete_before` | Grows with later phases | **91%** (260/285) |
| `storage-manager` | 2 | **100%** | Registry, writer task per sink, batching, retention, spool and replay, outage buffer, host cache, health | Wiring into `daemon status` (phase 10) | **90%** (977/1082) |
| `storage-sqlite` | 1, 2 | **100%** | Migration runner, every state store and event sink method incl. retention, worker thread, health; passes both suites on file and in memory | — | **94%** (624/666) |
| `storage-postgres` | 12 | **~15%** | v1 and v2 migrations and seeds, factory, stubs | All of it | **3%** (3/112). Conformance tests skipped. |
| `enrich` | 3 | **100%** | `Enricher`; TLS ClientHello, HTTP heads, DNS answers and cache, QUIC Initial decryption and reassembly; every fixture end to end | Per-flow use in the pipeline (phase 5) | **95%** (592/622) |
| `secrets` | 3, 11 | **~60%** | `file:` references with owner / mode checks and key generation; `keychain:`, `dpapi:`, `secret-service:` parsed | OS store backends (phase 11), Windows ACL checks (phase 13) | **88%** (156/177) |
| Policy engine (`crates/policy`) | 4 | **0% code, design done** | Location, scores, threshold, ports and entropy rule decided; module signals defined | All code | n/a |
| `daemon` (`scribed`) | 0, 0b, 5 | **~32%** | Config loading and checks (modules included), logging, startup summary, folders, SQLite storage created and migrated, `ModuleHost` (modules get `data_dir`), module output queue stored, signal handling, exit codes | Sensor → enrichment → modules → policy → storage pipeline, run states, service-manager integration, dropping privileges | **95%** (1342/1410) |
| `sensor-pcap` | 6 | **~2%** | Stub (sends `Observation`s) | Capture and flow reassembly | **60%** (6/10), stub only |
| `sensor-linux` (eBPF) | 7 | **~2%** | Stub, Linux only | eBPF programs, loader, process lookup | n/a (not built on macOS) |
| `sensor-windows` (ETW) | 8 | **~2%** | Stub, Windows only | ETW session, DNS-client events, Npcap | n/a (not built on macOS) |
| macOS Network Extension | 9 | **0%** | README only | Swift extension, XPC bridge | n/a |
| Local API (`crates/api`) and `cli` | 10 | **~20%** | CLI parses every command with `clap`, exit codes; API location decided | gRPC API, `scribe daemon` and `scribe modules`; commands talk to nothing | **88%** (29/33, `cli` library only) |
| Alert outputs (`crates/alerts`) | 11 | **~5%** | Alert output interface | Notifications, log, webhook | n/a |
| UI (Tauri) | later | **0%** | Test folders and mock API data | Everything | n/a |
| Packaging | 13 | **~15%** | Release archives with checksums; release smoke test runs both binaries and checks the shipped config and the URL module | `.deb` / `.rpm`, MSI, notarized `.pkg`, signing | n/a |

**Product total:** 4,797 of 5,232 measurable lines covered (**91.7%**).
The coverage targets in the test approach (≥ 80% for `core` and the daemon config) are met.

## Test infrastructure, CI and data

| Module | Completion | What exists | Test coverage |
|---|---|---|---|
| `test-support` | **100%** | Test doubles (with module doubles and `RecordingEmitter`), packet builders (now QUIC Initials with `ring`), pcap writer, fixture generator | **92%** (1520/1656) |
| `storage-conformance` | **100%** | Suite every storage backend must pass, with module data | **98%** (348/354) |
| `sensor-conformance` | **100%** | Suite every sensor must pass (checks client bytes), plus the traffic generator | **41%** (86/210); the runner needs a real sensor |
| `module-conformance` | **100%** | Suite every module must pass | **85%** (245/289) |
| Test data | **100%** | 16 pcap fixtures (2 QUIC), all checked end to end; RFC 9001 / 9369 sample packets; 19 scenarios, raw sensor samples, v1 and v2 database snapshots | Checked by the fixture, end-to-end and snapshot tests |
| Fuzzing | **~60%** | 4 targets with seeds (`tls_client_hello`, `dns_message`, `quic_initial`, `http_request`); they compile on stable | Never run (needs Rust nightly) |
| End-to-end scripts | **100% scripted** | Linux, macOS, Windows | Never run (needs installers and CLI commands) |
| CI and versioning | **~90%** | 8 workflows; minimum-version job; release smoke test covers `scribed` and the URL module; Postgres job loads migration 0002 | Run locally only, not on GitHub |

**Overall:** 6,996 of 7,741 measurable lines covered (**90.4%**).

## What this means

- **Phases 0, 0b, 1, 2 and 3 are done.** Remaining effort: 88.5–111 days (106–133 with buffer); milestone M1: 35–42.5 days
  (OS secret stores moved from phase 3 to phase 11, +1–1.5 days).
- **The daemon has a skeleton to grow into:** each next phase plugs into `serve()` (the pipeline in phase 5, which feeds `ModuleHost::on_flow`) and reads its settings from the already-checked config.
- **Next steps** (plan milestone M1):
  0. Run the Tests and Release workflows on GitHub once (they have never run) and fix what they find.
  1. Phase 4: the policy engine in `crates/policy`, against the 19 scenarios, using the config values.
  2. Phase 5: the pipeline, with a QUIC reassembler per UDP flow and DNS responses fed to the `Enricher`.
  3. Apply for Apple's Network Extension entitlement (plan risk 1).
- **Not verified here:** the Linux and Windows code paths at run time, the GitHub workflows themselves,
  the Postgres migration 0002 (no local Postgres; the Tests workflow loads it) and the fuzz targets (no nightly).
  Local Linux / Windows compile checks leave out crates with C code (bundled SQLite, `ring`: the daemon, `enrich`,
  `secrets`, `module-url`, test crates); CI builds them natively.
