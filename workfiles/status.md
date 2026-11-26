# scribe readiness by module

As of the end of **phase 11** (2026-11-24, commits `2f6cf0e`…`7a84611` plus the docs commit), **milestone M1
is complete**: alerts leave `scribed` through its log and signed HTTPS webhooks, and reach the desktop through
the `scribe notify` agent in the user's session; threat lists download with integrity checks and keep their
last good copy; secrets can live in the macOS keychain, Windows DPAPI or the Linux Secret Service. Capture
runs on the pcap sensor everywhere (phase 6), with each connection's process from the OS socket table
(option P, 2026-11-24); the native sensors for Linux (7B) and Windows (8A) remain, and macOS stays on
the socket table (option 9B). Product code coverage is 89.7%.

**How this was measured**
- **Completion** is an estimate against each module's scope in [plan.md](plan.md).
- **Coverage** is line coverage from `cargo test --workspace --all-features` alone, measured with LLVM
  source-based coverage (rustup `llvm-tools`) on macOS, all rows re-measured after phase 11. 504 tests
  passed and 4 were skipped (Postgres
  conformance needs a database; sensor conformance needs privileges).
- Unit tests written inside source files (`#[cfg(test)]` modules) count as covered lines, which raises
  the percentages of `core`, `daemon` and `cli` somewhat. `crates/daemon/src/config/tests.rs` and
  `tests/` folders are excluded.
- Linux- and Windows-only code (memory lookup, journald) is compile-checked from macOS but only runs in CI.

## Phase 11 delivered (one commit per step)

| Step | Commit | Result |
|---|---|---|
| 1. Dispatcher and log | `2f6cf0e` | `scribe-alerts`: a thread, a queue of 256 and a per-minute rate limit per output, one summary of held-back alerts per minute; `LogOutput`; `[alerts] log`, `max_per_minute`, live on reload |
| 2. Desktop notifications | `1c5609b` | `scribe notify` agent (rate limit, `--min-score`, waits for scribed, shows missed alerts after a reconnect), login files for systemd, launchd and Windows in the release archives; `scribe alerts --watch` |
| 3. Webhooks | `68573eb` | `[[alerts.webhooks]]`: JSON signed in `X-Scribe-Signature`, retries on network errors, 429 and 5xx; `scribe-net` (https only except loopback, OS trust store or pin, same-origin redirects, timeouts, size cap) |
| 4. OS secret stores | `7250cb8` | `keychain:`, `dpapi:`, `secret-service:` in `scribe-secrets`; `store()`; `scribed --set-secret [--generate]` |
| 5. Threat-list downloads | `7a84611` | Background refresh, `sha256` pin, minisign signature, `max_entries`, last good copy in `data_dir` |
| 6. Docs | this commit | Plan, status, readme, specs, conventions, test list; coverage re-measured |

The Linux container suite (`scripts/build/linux.sh check`) passed after step 5: 505 tests, D-Bus
notification and Secret Service code included. Tests per tag: 16 smoke, 430 functional, 31 integration,
30 scenario.

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
| `core` | 0, 0b | **~95%** | Flow event with module notes, `Observation` (incl. `DnsResponse`), modes, sensor interface, clock, alert with notes, module data types, `VERSION`, units, platform defaults | Grows as later phases need shared types | **97%** (457/473) |
| `module-api` | 0b, 10 | **~98%** | `Module`, `Manifest` checks, `FlowHook`, `Source`, `Emitter`, `ModuleContext` (with `data_dir`), `ConfigDoc`, `Signal`, `Reload`, `RecordReader` for module API services | `ProbeHost` (native sensors) | **98%** (156/160) |
| `module-url` | 0b, 3, 10 | **100%** | Manifest, `[modules.url] query` and `hash_key`, request parser, all five `query` modes, flow hook, request counters kept across restarts; `Url` API service and `scribe url list` | — | **94%** (303/321) |
| `storage-api` | 0b, 1–2, 5, 10 | **100%** | Interfaces with module data, schema version 4 (process counters, `unresolved`, hourly buckets), alert notes and port, chain links, row codec, `delete_before`, `remove_from_baseline`, `alert_states` | — | **85%** (326/382) |
| `storage-manager` | 2 | **100%** | Registry, writer task per sink, batching, retention, spool and replay, outage buffer, host cache, health | Live limit changes on reload (later) | **94%** (1100/1172) |
| `storage-sqlite` | 1, 2, 5, 10 | **100%** | Migrations 1–4, every state store and event sink method incl. process counters and hourly buckets, worker thread, health; passes both suites | — | **94%** (763/815) |
| `storage-postgres` | 12 | **~50%** | Event sink: TLS forced off this machine (OS trust store via `scribe-net`), `credentials`, `schema`, migrations under an advisory lock, one-statement batches, retention, queries, health; passes the sink conformance suite and INT-15 against Postgres 16 (local container; the Tests workflow's Postgres job runs both) | State store (refused in config until then), `ca` and client certificates, least-privilege roles, heartbeats | measured after the next coverage run |
| `enrich` | 3 | **100%** | `Enricher`; TLS ClientHello, HTTP heads, DNS answers and cache (clearable), QUIC Initial decryption and reassembly | — | **95%** (609/638) |
| `secrets` | 3, 11 | **~95%** | `file:` references with owner / mode checks and key generation; macOS keychain, Windows DPAPI, Linux Secret Service; `store` and `scribed --set-secret` | Windows ACL checks (phase 13); keychain and Secret Service round trips not run in CI | **80%** (218/272) |
| `policy` | 4, 10 | **100%** | Signals, threat lists, `Policy::decide`; reload setters, learn countdown pause; alert state restored at start | — | **98%** (485/494) |
| `daemon` (`scribed`) | 0, 0b, 5, 6, 10, 11 | **~95%** | Pipeline, run states, reload, audit chain, services; platform sensor with the pcap fallback; the local API (read and control calls, access checks and audit, `grpc.health.v1`, module services), alert state restored at start, hourly buckets pruned; alert outputs and webhooks from `[alerts]`, threat-list downloads, `--set-secret` | Native sensors (phases 7–9) | **90%** (3747/4150) |
| Process attribution (`crates/process`) | P | **100%** | Socket tables on Linux, macOS, Windows; `Resolver`; `Attributed` wrapper on the pcap sensor; `[sensor] process_lookup` | Connections shorter than a lookup keep no process (native sensors, phases 7–9) | measured after the next coverage run |
| `sensor-pcap` | 6 | **100%** | Decoder, flow tracker, pcap replay, live capture (libpcap / Npcap at run time), device choice; conformance passes live on Linux | — | **82%** (676/827; live capture runs as root, measured in the container suite, not here) |
| `sensor-linux` (eBPF) | 7 | **100%** | Record layout and join (tested on every system); eBPF programs (`fentry/tcp_connect`, `fexit/udp_sendmsg`, socket filter), loader, `EbpfSensor`; executable path from the kernel (record v2); privilege split: as `[daemon] user` one thread keeps `CAP_BPF` / `CAP_PERFMON` / `CAP_NET_RAW` and restarts capture after hibernation (checked in the container: `scribed` as `nobody`, wake-up re-attaches, another user's process gets its path); passes sensor conformance and runs in `scribed` in the Linux build container (kernel 6.18 arm64); Sensor tests green on the Ubuntu x86_64 runner (runs `45658825832`, `45681534506` with the privilege split) | Kernel matrix green: 5.8, 5.15, 6.1, 6.18 on x86_64 (job `kernels`, virtme-ng, run `45712541202`); arm64 only in the build container (6.18) | record / owners / join measurable on macOS; the loader is not |
| `sensor-windows` (ETW) | 8 | **~95%** | Step 3 (Sensor tests runs `45730673139` and `45737042676` green on Windows: a standard user in the `scribe` group reads the status, 8 of 8 new flows attributed, 140 paths from the rundown; the installed service as `NT SERVICE\scribed` captures with ETW, `scribe` reaches it, `curl.exe` by another account gets its path): process paths from Kernel-Process (no rights over other processes), the service as `NT SERVICE\scribed` (installer, pipe client, CI step `windows-service-check.ps1`). Step 2 (Sensor tests run `45722367989`: `etw_sensor_conforms` green on the Windows runner, ETW alone; Tests run `45722363836` green): the real-time ETW session through `windows-sys` and `EtwSensor` (Npcap packets when it loads, ETW alone otherwise; the daemon's primary sensor on Windows with pcap as fallback), conformance test `etw_sensor_conforms`. Step 1 (Tests run `45719108985` green): Kernel-Network (12 / 28 / 42 / 58) and DNS-Client (3008) events parsed field by field, DNS answers passed on as DNS messages, flows from ETW alone (no Npcap); the join with packets shared with Linux (`scribe_process::join`); synthetic samples (FUN-SN03), all tested on every system | The Npcap mode on a machine with Npcap (hosted runners have none) | event layouts and join measurable on macOS; the session is not |
| macOS sensor (option 9B) | 9 | **100%** | pcap sensor with `libproc` attribution (option P); hit rate in `scribe daemon status` and health (`attribution_low`); 50 ms scan budget with back-off; load checks (one real read with 400 own connections: 4.7 ms, unprivileged) | The Network Extension (option 9A) is a later option, not planned. A root scan of every process is not measured | — |
| Local API (`crates/api`) and `cli` | 10, 11 | **100%** | gRPC protocol (no `protoc` needed), Unix socket and Windows named pipe with caller identity, access policy, limits; every `scribe` command incl. `scribe daemon …`, `scribe modules`, `scribe audit verify`, `scribe url list`, `scribe alerts --watch`, `scribe notify`, `--json`, `--watch` | — | **94%** (261/279) `api`, **85%** (910/1075) `cli`; the named pipe runs only on the Windows CI runner |
| Alert outputs (`crates/alerts`) | 11 | **100%** | Dispatcher (queue and rate limit per output), log, signed webhook; desktop notifications through `scribe notify` | — | **96%** (288/300) |
| Outgoing HTTPS (`crates/net`) | 11 | **100%** | HTTP/1.1 client on rustls: https only except loopback, OS trust store or pin, same-origin redirects, timeouts, size cap; webhook signature | Proxies (not planned) | **90%** (482/534) |
| UI (Tauri) | later | **0%** | Test folders; mock API data in the protocol's JSON, checked against it; `MockApiServer` / `scribe-mock-api` serve it | Everything | n/a |
| Packaging | 13 | **~20%** | Release archives with checksums, service files (systemd unit, launchd plist, Windows install script) and `scribe notify` login files; manual install / uninstall scripts `scripts/install/` (green on Linux, macOS and Windows in Sensor tests run `45751039049`: install, a `scribe` group member reads the status, upgrade keeps the config, `--purge` leaves nothing); release smoke test | `.deb` / `.rpm`, MSI, notarized `.pkg`, signing, hardened units | n/a |

**Product total:** 10,784 of 12,017 measurable lines covered (**89.7%**); the new code for other systems (DPAPI, Secret Service, D-Bus) is not measurable on macOS.
The coverage targets in the test approach (≥ 80% for `core` and the daemon config) are met.

## Test infrastructure, CI and data

| Module | Completion | What exists | Test coverage |
|---|---|---|---|
| `test-support` | **100%** | Test doubles (with process counters and hourly buckets in `MemoryStore`), packet builders, pcap writer, fixture generator, `MockApiServer` | **90%** (1971/2182) |
| `storage-conformance` | **100%** | Suite every storage backend must pass, with module data, process counters, `unresolved`, hourly buckets, baseline removal and alert-state listing | **99%** (503/509) |
| `sensor-conformance` | **100%** | Suite every sensor must pass, now with stop / start; `names_flows` for sensors that leave naming to enrichment | **34%** (86/252); runs with a real sensor |
| `module-conformance` | **100%** | Suite every module must pass | **85%** (245/289) |
| Test data | **100%** | 16 pcap fixtures (2 QUIC), all checked end to end; RFC 9001 / 9369 sample packets; 19 scenarios (all run), raw sensor samples, v1–v4 database snapshots, 10 UI mock API scenarios checked against the protocol | Checked by the fixture, end-to-end, scenario and snapshot tests |
| Fuzzing | **~60%** | 4 targets with seeds (`tls_client_hello`, `dns_message`, `quic_initial`, `http_request`); they compile on stable | Never run (needs Rust nightly) |
| End-to-end scripts | **100% scripted** | Linux, macOS, Windows | Never run (needs installers and CLI commands) |
| CI and versioning | **~90%** | 8 workflows; minimum-version job; release smoke test covers `scribed` and the URL module; Postgres job loads migrations 0001–0004 and their seeds | Tests green on all jobs after 8A step 2 (run `45722363836`, commit `0d53717`) and Sensor tests on Windows (run `45722367989`: `etw_sensor_conforms` passed, event layouts and loopback events confirmed; pcap skipped without Npcap); after 8A step 1 (run `45719108985`, 2026-11-25, commit `d60b2fd`: ETW event layouts, DNS answers and ETW-only flows tested on Linux, macOS and Windows; join moved to `scribe-process`), after phase 7 step 4, the privilege split (run `45681530177`, 2026-11-25, commit `e539c3e`), and Sensor tests (run `45681534506`) green on Ubuntu x86_64 (`ebpf_sensor_conforms`, `pcap_sensor_conforms` and `privileges_keeper_restarts_capture_as_a_user` as root) and macOS (pcap), Windows failing only because the runner has no Npcap (known gap); after phase 7 steps 1–3 (run `45658820882`, 2026-11-25, commit `79a513a`: eBPF programs built in CI, MSRV job included) and Sensor tests green on Ubuntu x86_64 (run `45658825832`: `ebpf_sensor_conforms` and `pcap_sensor_conforms` as root); after option 9B was finished (run `45648605321`, 2026-11-25, commit `36d129a`: attribution hit rate, scan budget, live load check on all three systems), after the supply-chain checks and the Postgres sink (run `45533785706`, 2026-11-25, commit `6debbc1`: first `cargo deny` job, sink conformance and INT-15 against Postgres 16), after option P (run `45521781418`, 2026-11-25, commit `23d27b7`) and after phase 11 (run `45452687480`, 2026-11-24, commit `44f0c44`, after Windows test fixes for run `45448523591`); after phase 10 run `45226370809` (460 / 459 / 414 tests; Postgres job loads migrations 1–4); Release run `45322623374` (2026-11-23) published `v0.2.0` for all four targets with `SHA256SUMS`; Sensors, E2E, Fuzz and UI not run yet |

**Overall:** 13,589 of 15,249 measurable lines covered (**89.1%**).

## What this means

- **Phases 0, 0b, 1–7, 9 (9B), 10 and 11 are done: milestone M1 is complete, M2 needs only the Windows ETW sensor (8A).** Remaining effort: 15–22 days (19–27 with buffer), with the Linux sensor as option 7B (`libbpf-rs`, C eBPF programs) and macOS on option 9B; option 9A (Network Extension, 13–17 days) stays outside the totals.
- **`scribed` runs end to end with the pcap sensor, is controlled through `scribe` and tells people:** log, signed webhooks and desktop notifications (`scribe notify`), threat lists from files or checked downloads, secrets in the OS key stores.
- **Next steps:**
  1. M1 tagged as `v0.3.0-alpha.2` (2026-11-25, Bump version; Tests green in run `45533785706`). The Network Extension entitlement is needed only if option 9A is picked later.
  2. Option P (process attribution from the OS socket tables) is implemented and green on all three systems (run `45521781418`). Next from
     [plan.md, *Options for the stubbed phases*](plan.md#options-for-the-stubbed-phases): the Postgres event sink (12C), supply-chain
     checks (14) — both done and green in run `45533785706` — then the native sensors for Linux (7B) and Windows (8A). macOS stays on option 9B, finished 2026-11-25 (hit rate in status and health, scan budget, load checks; green in run `45648605321`).
  3. Linux eBPF sensor (7B) done (2026-11-25): sensor conformance and capture after dropping root pass on Linux 5.8, 5.15,
     6.1 and 6.18 (x86_64, Sensor tests run `45712541202`) and in the Linux build container (6.18, arm64); `scribed` runs it as
     `[daemon] user` with only the capture capabilities kept on one thread. Next: the Windows ETW sensor (8A).
- **Not verified here:** the eBPF sensor on kernels outside the matrix (x86_64: 5.8, 5.15, 6.1, 6.18 in run `45712541202`) and on arm64
  kernels other than the build container's 6.18; distribution kernels (the matrix uses Ubuntu mainline builds); the pcap sensor on Windows runners (no Npcap installed); Windows toasts (DPAPI and the `scribe notify` agent over the named pipe passed in run `45452687480`); real desktop notifications on any system (the agent is tested with a fake notifier); keychain and Secret Service round trips (gated: `SCRIBE_TEST_KEYCHAIN=1`, a desktop keyring); the Linux and Windows code paths beyond the Tests workflow, the workflows other than Tests and Release,
  the Postgres state store (not built; the event sink passed its conformance suite and INT-15 in run `45533785706`), the Windows named pipe outside the Windows runner (its tests passed there in run `45226370809`) and the fuzz targets (no nightly).
  Local Linux / Windows compile checks leave out crates with C code (bundled SQLite, `ring`: the daemon, `enrich`,
  `secrets`, `module-url`, test crates); the Tests workflow builds and passes them natively.
