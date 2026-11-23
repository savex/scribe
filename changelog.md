# Changelog

All notable changes to scribe, newest first. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions come from `v*` git tags (see [readme.md](readme.md#versioning)).

Every commit that changes behaviour, configuration, interfaces, tooling or documents adds a line under
**Unreleased**. On release, **Bump version** turns that section into the new version.

Sections: **Added**, **Changed**, **Deprecated**, **Removed**, **Fixed**, **Security**.

## [Unreleased]

### Added
- Phase 4 step 1: `scribe-policy` crate with the built-in signals (raw IP, TLD, Shannon entropy, usual ports)
  and threat lists (`domains`, `hosts`, `ips` with CIDR; subdomains match; bad lines skipped and counted).
- Phase 4 step 2: policy engine (`Policy::decide`): the specs 8.1 mode table, scoring with built-in and module
  signals, learn timer, dedupe per host + process from the last alert, acknowledgement, alert updates when a
  repeat brings new notes. `Alert` now carries the flow's notes.
- Phase 4 step 3: `[policy.scores]` takes module signal scores (`"<module>.<reason>" = 0–100`, module must be
  enabled; checked with line numbers). `scribed` builds the policy from its settings, reads the baseline and
  loads threat lists from files at start (a missing file stops it; `url` lists wait for phase 11).
- Phase 4 step 4: scenario runner (`tests/scenario`, YAML via `serde_yaml_ng`): one test per scenario file,
  played through `ModuleHost`, `Policy` and `MemoryStore`; 16 of 19 pass, 3 wait for phase 5 run states and
  per-process counters (ignored with the reason).
- Phase 4 step 5: the runner refuses bad scenario files with the line (SCN-26). Spec (rules settled in 8.3,
  FR-11–15), skill, plan (phase 4 done, rate limits to phase 11), status (coverage 92.1%), test list, test
  approach, scenario README and readme updated.
- Phase 5 step 1: `scribe_daemon::pipeline`: observation → DNS cache / enrichment → modules → policy → writes
  (flow and alert events, host deltas, learned baseline entries, alert state) and runtime counters; QUIC flows
  wait up to 1 s for a ClientHello split over several datagrams. `FlowKind::DnsResponse` carries DNS answers;
  alert records keep the port and the flow's notes.
- Phase 5 step 2: schema v3 (`0003_processes.sql`, SQLite and Postgres): per process + host counters
  (`process_hosts`, `StateStore::process_hosts`) and a sticky `hosts.unresolved` flag; snapshots `v3.db`,
  `v3_seed.sql`; two conformance cases.
- Phase 5 step 3: `scribed` runs the capture pipeline: sensor thread → bounded queue → pipeline → storage,
  alerts logged (`scribe::alert`), held QUIC flows judged every second, queued observations processed at
  shutdown; known processes loaded from storage. `serve_with` takes a sensor (tests). The scenario runner
  uses the real pipeline: `counters-exact` passes (17 of 19). Integration test INT-10.
- Phase 5 step 4: run states in the daemon: `Pipeline::hibernate` / `wakeup` (capped by the new
  `[daemon] max_hibernate`, `hibernated` alert, `audit` events, modules and the learn countdown paused, flows
  dropped and counted), timer wakeup on the tick, `reset` of counters and caches, a status snapshot, and
  `serve_controlled` with `Command`s that stop and restart the sensor. All 19 scenarios pass.
- Phase 5 step 5: config reload (`Command::Reload`, SIGHUP on Unix): the start file is re-read and checked;
  mode, profile, policy (threat files re-read), modules, `[daemon]` and the log level apply live; storage, sinks,
  limits and log output report "needs restart"; a broken file changes nothing. Spec 8.5.2 updated to match.
- Phase 5 step 6: tamper evidence and start checks: audit and alert records carry `seq` and `prev_hmac`
  (HMAC-SHA256, key `audit.key`, chain continues across restarts, `chain::verify` finds gaps and edits);
  `audit` events for start, stop and an unclean previous stop; `scribed` refuses to start when the config file
  or `data_dir` is writable by group or others.
- Phase 5 step 7: service integration: systemd `Type=notify` readiness, a systemd unit and a launchd plist,
  `scribed --service` for the Windows service control manager (`windows-service` 0.8) with an install script,
  service files in the release archives, and `[daemon] user` to drop root privileges on Unix.
- Phase 5 step 8: integration tests for module output and state across restarts (INT-05, INT-06), hosts and
  baseline across restarts (SCN-20) and isolated profiles (SCN-25). Spec, skill, plan (phase 5 done; hourly
  buckets and alert-state restore to phase 10), status (coverage 91.7%), test list, test approach, scenario
  README and readme updated.
- Plan: proposed local build scripts per host (macOS in Terminal or Xcode, Linux in a native `arm64` container or
  WSL2, Windows x64), risk 10 (Rosetta retirement after macOS 27) and an open decision on the
  `x86_64-apple-darwin` release target.
- Build scripts per system (`scripts/build/`): `macos.sh` (Terminal and Xcode, universal binaries),
  `linux.sh` (Apple `container`, docker or podman with a native arm64 image that cross-compiles x86_64, or
  `--native`), `windows.ps1` (PowerShell, Windows x64); shared `config`; `release` makes the same `dist/`
  archives and `SHA256SUMS` as the Release workflow. `dist/` is git-ignored.
- Phase 6 step 1: pcap sensor decoding (`scribe_sensor_pcap::decode`): Ethernet with VLAN tags, BSD loopback,
  raw IP, Linux cooked v1 / v2; IPv4 and IPv6 (extension headers skipped, fragments left out); TCP and UDP.
  A classic pcap file reader (`file`), both byte orders, µs / ns. Smoke test SMK-13 reads every fixture.
- Phase 6 step 2: flow tracking (`scribe_sensor_pcap::flows`): TCP flows from the client's SYN with their first
  bytes reassembled in or out of order (whole ClientHello, HTTP head, or first segment; reported after 1 s
  otherwise), later HTTP requests as `Payload` when modules need payload, UDP flows, QUIC follow-up Initials,
  DNS answers as `DnsResponse`, `Close` with the remaining bytes (FIN, RST, idle), local-address filtering, a
  bounded table, and `replay` for pcap files (FUN-SN01). The pipeline counts a `Close`'s bytes.
- Phase 6 step 3: live capture: libpcap / Npcap loaded at run time (`libloading`, `SCRIBE_LIBPCAP` to override;
  no SDK at build time), non-blocking reads so `stop` never waits for traffic, device choice (`[sensor]
  interface`, default Linux `any` or the first interface that is up), local addresses from every device.
  `scribed` falls back from the native sensors (Linux, Windows) to pcap when they can't start; macOS uses
  pcap. `Sensor::set_payload` tells sensors whether modules need payload.
- Fixed a flaky URL `hash` test: it failed when the random 6-digit hash contained "42"; it now checks that
  the query is gone.
- Phase 6 step 4: the sensor conformance suite stops and starts the sensor again; `names_flows` leaves host
  names and security to enrichment for pcap. The pcap sensor passes the suite live on Linux (`scripts/build/
  linux.sh run …` as root in the container). INT-09: every fixture through pcap replay and the daemon
  pipeline, replacing the test-side frame reader (INT-18).
- Phase 6 step 5: spec 8.4.1 (pcap sensor rules), FR-1 / FR-2 and fallback statuses, skill, plan (phase 6
  done), status (coverage 90.6%), test list, readme.

### Changed
- Workflows use the Node.js 24 action versions (`checkout@v5`, `upload-artifact@v6`, `download-artifact@v7`,
  `setup-node@v5`); the config template notes how to write Windows paths in TOML.
- Bump version works from the highest known version (latest tag by SemVer order, `Cargo.toml`, `changelog.md`),
  warns when they differ, refuses a version that is not newer, and turns Unreleased into the release section.
  `scripts/version.sh` gains `versions`, `highest`, `nearest-tag`, `changelog-version`, `newer`, `compare` and
  `changelog`; `latest-tag` is now the highest tag, not the nearest. Tests run `scripts/test-version.sh`.

### Fixed
- Config, secrets and URL-module tests are portable to Windows (absolute paths, `\` joins, TOML escapes), the
  9 failures in Tests run 2; plan, status and skill no longer cite Version tracking run `45072299330` as green Tests.
- Changelog: the `0.1.0-alpha.1` release had no section (the workflow did not write one).
- Plan and status cited phase 4 commit ids from before the rebase onto the release commit.
- `Cargo.lock` listed `scribe-policy` at 0.1.1 after the rebase onto the release; `--locked` builds failed.
- Fuzz target `http_request` flagged any `@` in the URL as user info; it now checks the authority only. The
  parser was right (an `@` in a query is data). Regression test and an `at_in_query` fuzz seed added.

## [0.1.0-alpha.1] - 2026-11-22

Released by Bump version (tag `v0.1.0-alpha.1` on `24550a2`). The workflow started from `0.0.0` because the
`v0.1.1` tag was never pushed, so this version sorts below 0.1.1. Phases 0b to 3, the storage manager and
enrichment.

### Added
- Module framework (phase 0b):
  - `scribe-module-api` crate: `Module`, `Manifest`, `FlowHook`, `Source`, `Emitter`, `ModuleContext`.
  - `ConfigDoc` reads `[modules.<id>]` and keeps exact error lines.
  - Flow notes, module records and metric samples in `scribe-core`.
  - `scribe-module-conformance`: the suite every module must pass. It catches 7 injected faults.
  - Module test doubles: `TagModule`, `TicksModule`, `NoopModule`, `MisbehavingModule`, `RecordingEmitter`.
  - URL module skeleton `scribe-module-url`. Its parser stays a stub until phase 3.
  - `[modules]` config: `enabled = ["url"]` by default, one checked table per module.
  - `url` Cargo feature, on by default.
  - `ModuleHost` in `scribed`: hook time budget, panic isolation, source ticks, pause / resume / stop.
  - Bounded module output queue; drops are counted.
- Storage for module data:
  - `EventKind::Metric` and `EventKind::Module("<module>.<name>")`.
  - `StoredEvent::Metric` and `StoredEvent::Module`.
  - Module state in `StateStore` (`module_state`, `put_module_state`).
  - Schema v2: migration `0002_modules.sql`, `metrics` and `module_state` tables.
  - Snapshots `sqlite/v2.db` and `postgres/v2_seed.sql`.
  - Sinks can subscribe to `metric` and module kinds such as `url.request`.
- SQLite backend (phase 1):
  - `rusqlite` 0.43 with bundled SQLite.
  - Opens on first use; WAL mode, 5 s busy timeout.
  - Migration runner. Refuses a database newer than the build.
  - State store: delta counters, sticky flags, IP links, baselines, alert and module state.
  - Event sink: transactional batches, merged time-ordered queries with totals.
  - Passes both storage conformance suites. Reads the v1 and v2 snapshots.
- Shared row codec `scribe_storage_api::codec` for SQLite and Postgres. It reads schema 1 rows.
- `StorageError::Data` for unreadable records.
- `scribed` creates `state.db` and `events.db` and logs `storage ready`.
- `--check-config` prints each module's settings. The startup summary lists modules.
- Release smoke test checks that the shipped config enables the URL module.
- Spec and plan:
  - `scribe daemon` subcommands: `status`, `health`, `reset`, `hibernate [--for]`, `wakeup`.
  - Daemon run states and config reload rules.
  - Security design for every interaction (specs 12.1.1, NFR-17 – NFR-19).
  - Module framework design (specs 7.4) and SQLite backend notes (specs 10.4).
  - Secrets crate planned for phase 3.
  - "Decisions needed before a phase" table.
  - Risk 9: CI has never run on GitHub.
- Diagrams: module framework, daemon run states, schema v2 tables, local API trust boundary.
- `FlowEvent.ech` and `FlowEvent::unresolved()` (FR-5, FR-7); the builder gains `ech()`.
- Fixture `http_keepalive`: two HTTP requests on one connection. Fixture expectations gain `kind`.
- Sensor sample `linux-ebpf/http_keepalive.json`. Samples list `observations` (with client bytes) and `enriched`.
- 8 scenarios: unusual port (2), new TLD, threat list, acknowledged alert, module signal, hibernate cap, wakeup and reset.
- Scenario format: `api` actions (`ack`, `baseline_add`, `hibernate`, `wakeup`, `reset`), `ech`, `head_bytes`, `threat_list`, `scores`, `modules`.
- Scenario expectations: `notes`, `unresolved`, `processes`, `signals`, `run_state`, `runtime`.
- UI mocks: `hibernating`, `degraded-drops`, `module-failed`; statuses carry run state, counters, critical metrics, modules.
- Spec: `--json` for `scribe hosts` and `scribe alerts`; `scribe baseline` lists entries.
- `workfiles/test-list.md`: catalogue of the fast tests with tags (`smoke`, `functional`, `integration`,
  `scenario`), isolation and parallel rules, and a 60 s budget (120 s with contingency).
- Test tags: every test sits in `smoke::`, `functional::` or `integration::` (`scenario::` when the runner lands).
- `scripts/check-test-tags.sh` fails on untagged tests; it runs in the Tests workflow.
- `cargo-nextest` with `.config/nextest.toml`: per-test time limits, a `ci` profile with JUnit output.
- `scribe-tests` crate (`tests/`): smoke, integration and scenario test binaries, shared helpers, and test
  builds of `scribed` / `scribe`.
- `EventSink::delete_before` for retention (SQLite, in-memory doubles; Postgres in phase 12); the storage
  conformance suite checks it for sinks without native retention.
- Storage manager runs: `StorageManager::start` gives a `Storage` with one writer task per sink. Batches by
  size and time, non-blocking `publish` (full queues drop and count), hourly retention for sinks without their
  own, per-sink counters (`sink_status`), flush and shutdown.
- On-disk spool per sink (`storage.spool`): failed batches wait there, new batches queue behind them, replay
  is in order with doubling back-off (1 s to 60 s); size and free-disk limits drop the oldest and count; a spool
  left by an earlier run is replayed at start.
- State-store outage buffer (`storage.buffer`): failed writes and all later ones wait in order, the oldest is
  dropped at the count or memory limit, replay runs with back-off; IP links follow buffered hosts; writes that
  can never succeed are dropped on replay; health is degraded while buffering.
- Host and baseline cache (`storage.cache`): least recently used hosts evicted at the count or memory limit,
  writes update cached entries, `clear_cache` for reset. `Storage::health` gives the worst of state store and
  sinks (spooling or drops make a sink degraded).
- Storage tests: SQLite in-memory conformance, a counter property test, four writers on one SQLite file, and an
  integration test of the running storage (writers, spool, buffer, cache) over SQLite.
- Phase 3 step 1: TLS ClientHello parser in `scribe-enrich` (`parse_client_hello`): SNI (checked, lowercase),
  ECH flag, ALPN, TLS 1.3 offer; reassembles a hello split over several records; never panics. The test
  ClientHello builder can add ALPN.
- Phase 3 step 2: HTTP request heads in `scribe-enrich` (`parse_request_head`, `host_header`, `split_host_port`);
  the URL module parses requests (origin and proxy form, user info removed, odd ports kept) and applies
  `full`, `redact_values`, `strip` and `path_only` exactly as the specs 12.2 examples; `url.request` records
  carry `method` and `url`.
- Phase 3 step 3: DNS response parser (compressed names with a jump limit, A / AAAA / CNAME) and a `DnsCache`
  on `Clock` that maps answer IPs to the queried name through CNAME chains, with the shortest TTL on the chain,
  a one-day cap and an entry limit.
- Phase 3 step 4: `Enricher` sets security, the ECH flag and the host name (SNI, then `Host`, then the sensor's
  name, then the DNS cache); it learns from raw DNS responses or OS-decoded answers. Integration test INT-08.
- Phase 3 step 5: `scribe-secrets` crate: secret references (`file:` implemented with owner and mode checks and
  race-safe key creation; `keychain:`, `dpapi:`, `secret-service:` parsed, backends in phase 11).
  URL `query = "hash"` now works: HMAC-SHA256 (ring), first 6 hex digits, key from `[modules.url] hash_key`
  or `url_hash.key` in `data_dir`. `ModuleContext` gains `data_dir`.
- Phase 3 step 6: QUIC Initial decryption with `ring` (v1 and v2, header protection, AES-128-GCM, CRYPTO
  frame reassembly across packets); the enricher turns UDP flows with a client Initial into named QUIC flows.
  Checked against the RFC 9001 and RFC 9369 sample packets. Fixtures `quic_initial`, `quic_split_hello`.
- Phase 3 step 7: fuzz targets `dns_message` and `quic_initial` (plus `parse_client_hello` in `tls_client_hello`),
  their seeds in `fixtures.rs`, and a test that runs the seeds through the parsers. Fuzz workflow lists all four.
- Phase 3 step 8: every pcap fixture runs end to end through the enricher and the URL module (INT-18); UDP
  flows are classified (QUIC long header or plaintext). Spec, skill, plan (phase 3 done; OS secret stores
  moved to phase 11), status (coverage 91.7%), test list, test approach and diagram updated.
- Plan and status record the first green Tests workflow on GitHub (2026-11-22); risk 9 narrowed to the
  workflows that have not run yet.
- Readme rewritten for users: what scribe does, how it works (diagrams), privacy, configuration, status,
  CI badges; developer details moved to the end.

### Changed
- `FlowEvent.url` is now `FlowEvent.notes`; the URL module writes `notes.url`.
- `FlowKind::Request` is now `FlowKind::Payload`.
- Sensors send `Observation`s: the event plus up to 4 KiB of client bytes.
- `FakeSensor` replays on every start. The flow builder gains `payload`, `http_get`, `note`, `observe`.
- The sensor conformance suite checks client bytes instead of URLs.
- pcap fixtures expect `notes.url`.
- `SCHEMA_VERSION` is 2.
- The HTTP request parser and its fuzz target moved to the URL module. `scribe-enrich` keeps a `host_header` stub.
- `testdata/db/build.sh` only writes missing snapshots; `--force <version>` rebuilds one.
- Shipped `config/scribe.toml`: `[privacy]` replaced by `[modules]` and `[modules.url]`.
- `CLAUDE.md`: new modules must pass `scribe-module-conformance`.
- Plan: phases 0b and 1 done; phases 2, 3, 4 re-scoped. 101.5–127.5 days left (122–153 with buffer); M1 48–59.
- Diagrams and test approach updated after phase 1. Test workflows are described as manual.
- Status: 91.7% product test coverage.

- DoH fixture and `hostname-unresolved` use `doh.example.net` at 198.51.100.53, not a real resolver.
- `traffic.env` has no internet defaults; e2e scripts stop while a target is empty.
- E2e scripts upgrade from the previous release and check data, mode, schema, config and the URL module.
- E2e scripts check security (groups, file modes, socket dir, systemd hardening), daemon commands and uninstall data.
- E2e scripts read `--json` output and poll with a timeout instead of sleeping.
- `counters-exact` checks per-process counters; `caution-plaintext-known-host` checks the alert's URL note.
- v2 snapshot rebuilt (not yet released): its flow row has `src` and `ech`.
- Test data rules: no exceptions to documentation addresses and example names.
- Tests workflow: smoke first, then the fast run with nextest; fails over 120 s; doc examples run separately.
- `built_in_registry_has_sqlite` split into a smoke and an integration test; `catches_every_fault` into 7 tests.
- The module suite's quiet panic hook is thread-local, so parallel tests keep their panic output.
- `CLAUDE.md`: tag and isolation rules; nextest and the tag check before committing.
- Test layout (hybrid): 13 smoke and 5 integration tests moved to `tests/`; each crate's tests now form one
  `tests/functional/` binary; 51 source-file tests that use only public code moved there too. 49 tests that
  need private code stay in `src/`.
- Tag check reads `cargo nextest list`: a test's tag is its binary (`smoke`, `functional`, …) or its module.
- Sensor tests workflow selects `traffic_generator::` and `sensors::` inside the `functional` binary.
- SQLite runs on a worker thread per database; calls return futures that work on any executor and never
  block the async runtime.
- `scribed` publishes module output through the running storage and drains the writers on shutdown.
- Documents after phase 2: spec 0.10 (10.5 storage manager; FR-17, FR-19, FR-25, NFR-7 implemented), skill,
  plan (95.5–120.5 days left, M1 42–52), status (90.2% product coverage), test list and test approach.

### Deprecated
- `privacy.url_query`. Use `[modules.url] query`. The old key still works, with a warning, for one minor version.

### Fixed
- Tests workflow: the SQLite job always runs its tests. The manual input now adds only Postgres tests.
- Plan: stale header, progress and phase statuses after phase 1.
- Plan: removed "rare host"; it was in neither the spec nor the config.
- Plan totals were half a day too high after the `scribe daemon` change. Later totals are correct.
- Skill milestone figures were stale.
- Workspace version synced to 0.1.1 to match the `v0.1.1` tag.

## [0.1.1] - 2026-11-08

First tagged version (`v0.1.1` on `5ff4049`; no `v0.1.0` tag exists). Scaffold, test infrastructure,
design documents and phase 0.

### Added
- Workspace: `scribed` daemon, `scribe` CLI, core types, enrichment, sensor stubs, storage interfaces.
- SQLite and PostgreSQL backend stubs with v1 schemas.
- Test infrastructure: test doubles, packet builders, pcap writer, `gen-fixtures`.
- Storage and sensor conformance suites.
- Test data: 13 pcap fixtures, 11 scenarios, raw sensor samples, schema snapshots, fuzz targets, UI mocks.
- End-to-end scripts.
- Tag-based versioning (`scripts/version.sh`, `--version` on both binaries).
- 8 GitHub workflows; only Release and Version tracking run automatically.
- VSCodium configuration.
- Documents: plan, diagrams, test approach, status, spec, conventions skill, `CLAUDE.md`, this changelog.
- Config format v1 (`config/scribe.toml`) with every default.
- Units: durations, sizes and percentages with clear errors.
- Platform defaults: paths per OS, total RAM, volume size.
- Config loading: `--config`, `SCRIBE_CONFIG`, OS default, built-in defaults.
- Config errors name the file, line and column.
- Logging: level with `SCRIBE_LOG`, text or JSON, file rotation, journald, unified logging, stderr fallback.
- `scribed`: `--config`, `--check-config`, `--version`. Stops cleanly on Ctrl-C or SIGTERM.
- `scribed` exit codes: 0 ok, 1 failure, 2 usage or config error.
- `scribe` CLI parses all commands; only `version` works.
- Storage manager tests: registry, routing, errors.
- Release smoke test runs both binaries and checks the shipped config.

### Changed
- Phase 0 dependencies added. `StorageError` and `SensorError` use `thiserror`.
- Minimum Rust version policy: follow dependencies. Raised from 1.70 to 1.89.

### Fixed
- Restored spec sections 9.2 and 9.3, lost in an earlier edit.

### Removed
- `config/scribe.example.toml`, replaced by `config/scribe.toml`.

[Unreleased]: https://github.com/savex/scribe/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/savex/scribe/releases/tag/v0.1.0-alpha.1
[0.1.1]: https://github.com/savex/scribe/releases/tag/v0.1.1
