# Changelog

All notable changes to scribe, newest first. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions come from `v*` git tags (see [readme.md](readme.md#versioning)).

Every commit that changes behaviour, configuration, interfaces, tooling or documents adds a line under
**Unreleased**. On release, **Bump version** turns that section into the new version.

Sections: **Added**, **Changed**, **Deprecated**, **Removed**, **Fixed**, **Security**.

## [Unreleased]

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

[Unreleased]: https://github.com/savex/scribe/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/savex/scribe/releases/tag/v0.1.1
