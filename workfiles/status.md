# scribe readiness by module

As of the end of **phase 10** (2026-11-23, commits `920c906`…`985bf24` plus the docs commit), **scribe is
controlled through its local API**: `scribed` serves read and control calls over a Unix socket (a named pipe on
Windows) with the caller's identity from the OS, access checks and an audit event for every control call, and
every `scribe` command works against it, `scribe daemon …`, `scribe audit verify` and `scribe url list`
included. Capture runs on the pcap sensor everywhere (phase 6); process attribution still waits for the native
sensors (phases 7–9). Product code coverage is 91.0%.

**How this was measured**
- **Completion** is an estimate against each module's scope in [plan.md](plan.md).
- **Coverage** is line coverage from `cargo test --workspace --all-features` alone, measured with LLVM
  source-based coverage (rustup `llvm-tools`) on macOS, all rows re-measured after phase 10. 459 tests
  passed and 4 were skipped (Postgres
  conformance needs a database; sensor conformance needs privileges).
- Unit tests written inside source files (`#[cfg(test)]` modules) count as covered lines, which raises
  the percentages of `core`, `daemon` and `cli` somewhat. `crates/daemon/src/config/tests.rs` and
  `tests/` folders are excluded.
- Linux- and Windows-only code (memory lookup, journald) is compile-checked from macOS but only runs in CI.

## Phase 10 delivered (one commit per step)

| Step | Commit | Result |
|---|---|---|
| 1. API crate | `920c906` | `proto/scribe/v1/api.proto` built with `protox` (no `protoc`), Unix socket transport, caller identity, access policy, limits |
| 2. Read calls | `cde939e` | `scribed` serves status (critical metrics), health and `grpc.health.v1`, hosts, alerts and their stream, baseline, export, modules; `[api]` config |
| 3. Control calls | `5ceb506` | Mode, baseline edits (`remove_from_baseline`), acknowledgements, reset / reload, hibernate, wakeup; audit events for every call and refusal |
| 4. CLI | `016d47b` | Every `scribe` command over the API, `--json`, `--watch`, aliases, exit codes, `--socket` / `SCRIBE_SOCKET` |
| 5a. Alert state, audit | `159623f` | Acknowledgements and dedupe restored at start (`alert_states`); `scribe audit verify` |
| 5b. Hourly buckets | `4b78d76` | Schema v4 `host_hours`, `[storage.hours] keep`, `scribe hosts --hourly`; snapshots v4 |
| 6a. Named pipe | `cdb1144` | Windows transport: access list, first instance, token identity, server check; `scribe_api::transport` |
| 6b. Module services | `985bf24` | `RecordReader`, the URL module's `Url` service, `scribe url list`, *module … is not enabled* |
| 7. Mocks and docs | this commit | `MockApiServer`, `scribe-mock-api`, UI mocks in the protocol's JSON with a smoke check, CLI scenario tests; docs |

## Phase 6 delivered (one commit per step)

| Step | Commit | Result |
|---|---|---|
| 0. Build scripts | `5fc08d0` | `scripts/build/` for macOS (Terminal, Xcode), Linux (container or native) and Windows |
| 1. Decoder | `f42a76b` | Link layers, IPv4 / IPv6, TCP / UDP; pcap file reader; SMK-13 |
| 2. Flow tracker | `fc1b908` | First bytes, later requests, QUIC follow-ups, DNS responses, closes with bytes; replay; FUN-SN01 |
| 3. Live capture | `bb0490e` | libpcap / Npcap at run time, non-blocking reads, device choice, native → pcap fallback |
| 4. Conformance | `b9a61ae` | Stop / start case; pcap suite passes live on Linux; INT-09 through the pipeline |
| 5. Docs | this commit | Spec 8.4.1, skill, plan, status, test list, readme |

## Phase 5 delivered (one commit per step)

| Step | Commit | Result |
|---|---|---|
| 1. Pipeline core | `39796b2` | `Pipeline::process`: DNS answers, enrichment, QUIC holding, modules, policy → writes; runtime counters |
| 2. Schema v3 | `a5b5fb8` | Per process + host counters, sticky `unresolved` flag; SQLite and Postgres migrations, snapshots, conformance |
| 3. `serve()` | `45175fc` | Sensor thread → bounded queue → pipeline → storage; alerts logged; scenario runner on the real pipeline |
| 4. Run states | `5102dc0` | Hibernate (capped, alerted, audited), wakeup, reset, status; `Command`s for the API; all 19 scenarios pass |
| 5. Config reload | `877accb` | SIGHUP and `Command::Reload`: live keys applied, restart keys reported, broken files refused |
| 6. Security | `a35b813` | Audit and alert chain (`seq`, `prev_hmac`), start / stop / unclean-stop audits, StrictModes |
| 7. Services | `173e2bf` | systemd `Type=notify` and unit, launchd plist, Windows service, `[daemon] user` privilege drop |
| 8. Tests and docs | this commit | Restart, module-state and profile integration tests; spec, skill, plan, status, test list, readme |

## Phase 4 delivered (one commit per step)

| Step | Commit | Result |
|---|---|---|
| 1. Signals | `9c36205` | `scribe-policy`: raw IP, TLD, Shannon entropy, usual ports; threat lists in three formats with CIDR |
| 2. Engine | `7646b71` | `Policy::decide`: mode table, scoring, reason order, learn timer, dedupe from the last alert, acknowledgement, notes on alerts |
| 3. Config | `34eadd8` | Module signal scores in `[policy.scores]` with line numbers; `scribed` builds the policy and loads threat list files |
| 4. Scenarios | `ef17bee` | Scenario runner, one test per file: 16 pass, 3 wait for phase 5 |
| 5. Docs | `424ce91` | Bad scenario files refused with their line (SCN-26); spec, skill, plan, status, test list, test approach, readme |

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
| `core` | 0, 0b | **~95%** | Flow event with module notes, `Observation` (incl. `DnsResponse`), modes, sensor interface, clock, alert with notes, module data types, `VERSION`, units, platform defaults | Grows as later phases need shared types | **97%** (420/432) |
| `module-api` | 0b, 10 | **~98%** | `Module`, `Manifest` checks, `FlowHook`, `Source`, `Emitter`, `ModuleContext` (with `data_dir`), `ConfigDoc`, `Signal`, `Reload`, `RecordReader` for module API services | `ProbeHost` (native sensors) | **98%** (156/160) |
| `module-url` | 0b, 3, 10 | **100%** | Manifest, `[modules.url] query` and `hash_key`, request parser, all five `query` modes, flow hook, request counters kept across restarts; `Url` API service and `scribe url list` | — | **94%** (303/321) |
| `storage-api` | 0b, 1–2, 5, 10 | **100%** | Interfaces with module data, schema version 4 (process counters, `unresolved`, hourly buckets), alert notes and port, chain links, row codec, `delete_before`, `remove_from_baseline`, `alert_states` | — | **85%** (326/382) |
| `storage-manager` | 2 | **100%** | Registry, writer task per sink, batching, retention, spool and replay, outage buffer, host cache, health | Live limit changes on reload (later) | **93%** (1013/1095) |
| `storage-sqlite` | 1, 2, 5, 10 | **100%** | Migrations 1–4, every state store and event sink method incl. process counters and hourly buckets, worker thread, health; passes both suites | — | **94%** (763/815) |
| `storage-postgres` | 12 | **~15%** | v1–v4 migrations and seeds, factory, stubs | All of it | **2%** (3/125). Conformance tests skipped. |
| `enrich` | 3 | **100%** | `Enricher`; TLS ClientHello, HTTP heads, DNS answers and cache (clearable), QUIC Initial decryption and reassembly | — | **96%** (609/638) |
| `secrets` | 3, 11 | **~60%** | `file:` references with owner / mode checks and key generation; `keychain:`, `dpapi:`, `secret-service:` parsed | OS store backends (phase 11), Windows ACL checks (phase 13) | **88%** (156/177) |
| `policy` | 4, 10 | **100%** | Signals, threat lists, `Policy::decide`; reload setters, learn countdown pause; alert state restored at start | — | **98%** (480/489) |
| `daemon` (`scribed`) | 0, 0b, 5, 6, 10 | **~95%** | Pipeline, run states, reload, audit chain, services; platform sensor with the pcap fallback; the local API (read and control calls, access checks and audit, `grpc.health.v1`, module services), alert state restored at start, hourly buckets pruned | Native sensors (phases 7–9) | **92%** (3855/4201) |
| `sensor-pcap` | 6 | **100%** | Decoder, flow tracker, pcap replay, live capture (libpcap / Npcap at run time), device choice; conformance passes live on Linux | — | **82%** (676/827; live capture runs as root, measured in the container suite, not here) |
| `sensor-linux` (eBPF) | 7 | **~2%** | Stub, Linux only | eBPF programs, loader, process lookup | n/a (not built on macOS) |
| `sensor-windows` (ETW) | 8 | **~2%** | Stub, Windows only | ETW session, DNS-client events, Npcap | n/a (not built on macOS) |
| macOS Network Extension | 9 | **0%** | README only | Swift extension, XPC bridge | n/a |
| Local API (`crates/api`) and `cli` | 10 | **100%** | gRPC protocol (no `protoc` needed), Unix socket and Windows named pipe with caller identity, access policy, limits; every `scribe` command incl. `scribe daemon …`, `scribe modules`, `scribe audit verify`, `scribe url list`, `--json`, `--watch` | — | **94%** (261/279) `api`, **92%** (754/819) `cli`; the named pipe runs only on the Windows CI runner |
| Alert outputs (`crates/alerts`) | 11 | **~5%** | Alert output interface | Notifications, log, webhook | n/a |
| UI (Tauri) | later | **0%** | Test folders; mock API data in the protocol's JSON, checked against it; `MockApiServer` / `scribe-mock-api` serve it | Everything | n/a |
| Packaging | 13 | **~20%** | Release archives with checksums and service files (systemd unit, launchd plist, Windows install script); release smoke test | `.deb` / `.rpm`, MSI, notarized `.pkg`, signing, hardened units | n/a |

**Product total:** 9,899 of 10,874 measurable lines covered (**91.0%**).
The coverage targets in the test approach (≥ 80% for `core` and the daemon config) are met.

## Test infrastructure, CI and data

| Module | Completion | What exists | Test coverage |
|---|---|---|---|
| `test-support` | **100%** | Test doubles (with process counters and hourly buckets in `MemoryStore`), packet builders, pcap writer, fixture generator, `MockApiServer` | **90%** (1931/2143) |
| `storage-conformance` | **100%** | Suite every storage backend must pass, with module data, process counters, `unresolved`, hourly buckets, baseline removal and alert-state listing | **99%** (503/509) |
| `sensor-conformance` | **100%** | Suite every sensor must pass, now with stop / start; `names_flows` for sensors that leave naming to enrichment | **34%** (86/252); runs with a real sensor |
| `module-conformance` | **100%** | Suite every module must pass | **85%** (245/289) |
| Test data | **100%** | 16 pcap fixtures (2 QUIC), all checked end to end; RFC 9001 / 9369 sample packets; 19 scenarios (all run), raw sensor samples, v1–v4 database snapshots, 10 UI mock API scenarios checked against the protocol | Checked by the fixture, end-to-end, scenario and snapshot tests |
| Fuzzing | **~60%** | 4 targets with seeds (`tls_client_hello`, `dns_message`, `quic_initial`, `http_request`); they compile on stable | Never run (needs Rust nightly) |
| End-to-end scripts | **100% scripted** | Linux, macOS, Windows | Never run (needs installers and CLI commands) |
| CI and versioning | **~90%** | 8 workflows; minimum-version job; release smoke test covers `scribed` and the URL module; Postgres job loads migrations 0001–0004 and their seeds | Tests green on Linux, macOS and Windows after phase 10 (run `45226370809`, 2026-11-23: 460 / 459 / 414 tests; Postgres job loads migrations 1–4); Release run `45322623374` (2026-11-23) published `v0.2.0` for all four targets with `SHA256SUMS`; Sensors, E2E, Fuzz and UI not run yet |

**Overall:** 12,664 of 14,067 measurable lines covered (**90.0%**).

## What this means

- **Phases 0, 0b, 1–6 and 10 are done.** Remaining effort: 59–75.5 days (71–91 with buffer); milestone M1: 5.5–7 days (phase 11).
- **`scribed` runs end to end with the pcap sensor and is controlled through `scribe`:** every CLI command works over the local API (Unix socket; named pipe on Windows). What M1 still needs is the alert outputs (phase 11).
- **Next steps** (plan milestone M1):
  1. Phase 11 (alert outputs) to finish M1.
  2. Apply for Apple's Network Extension entitlement (plan risk 1).
- **Not verified here:** the Linux and Windows code paths beyond the Tests workflow, the workflows other than Tests and Release,
  the Postgres backend beyond loading its migrations (run `45226370809` loads 0001–0004 and the seeds), the Windows named pipe outside the Windows runner (its tests passed there in run `45226370809`) and the fuzz targets (no nightly).
  Local Linux / Windows compile checks leave out crates with C code (bundled SQLite, `ring`: the daemon, `enrich`,
  `secrets`, `module-url`, test crates); the Tests workflow builds and passes them natively.
