# Changelog

All notable changes to scribe are recorded here, newest first.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow the
`v*` git tags described in [readme.md](readme.md#versioning).

Every commit that changes behaviour, configuration, interfaces, tooling or documents adds a line under
**Unreleased**. On release, **Bump version** turns that section into the new version's section.

Sections: **Added**, **Changed**, **Deprecated**, **Removed**, **Fixed**, **Security**.

## [Unreleased]

### Added
- Planned `scribe daemon` subcommands in the spec and plan: `status` (live counters and critical metrics),
  `health`, `reset` (counters, caches, config reload), `hibernate [--for]` and `wakeup`; daemon run states,
  config reload rules, read vs control API access; phases 5 and 10 re-estimated (+3.5 days).
- Proposed security design for every interaction in the spec (section 12.1.1, NFR-17 to NFR-19) and the
  conventions skill: local API access checks, XPC code signing, privilege split, TLS for Postgres / webhook /
  threat lists, encryption at rest, tamper evidence, release signing.
- Security design carried through the documents: capped and alerting `hibernate` (`daemon.max_hibernate`),
  API transport and server checks in the daemon commands, proposed security config keys (specs 9.1.1),
  security verification and test cases, open questions 11–13; plan spreads the work over phases 5–14
  (+14.5 days; totals 108–135 days, 99.5–125.5 remaining).
- Proposed module framework (specs 7.4, FR-32 – FR-35, NFR-20, schema v2 in 10.3): features as compiled-in
  modules with generic outputs (flow notes, module records, metric samples, module state), URL tracking as
  the first module, kernel metrics as the example of a later one; `privacy.url_query` to move to
  `[modules.url] query`. Plan adds phase 0b (8–10 days) and 2 days in phase 10; conventions skill section 9b,
  test approach section 7a, status updated.

- Phase 0b step 1: `scribe_core::module` (flow `Notes`, `ModuleRecord`, `MetricSample`) and the new
  `scribe-module-api` crate: `Module`, `Manifest` with naming checks, `FlowHook`, `Source`, `Emitter`,
  `ModuleContext`, `Signal`, `Reload`, and `ConfigDoc`, which reads `[modules.<id>]` with exact line numbers.

- Phase 0b step 2: `FlowEvent.url` replaced by module `notes`; `FlowKind::Request` renamed `Payload`. Sensors
  now send `Observation`s (event plus up to `HEAD_MAX` = 4 KiB of client bytes). `FakeSensor` replays
  observations on every start; `FlowBuilder` gains `payload`, `http_get`, `note` and `observe`. The sensor
  conformance suite checks the client bytes instead of the URL; pcap fixture expectations moved to `notes.url`.

- Phase 0b step 3: storage interface for modules. `EventKind` gains `Metric` and `Module("<module>.<name>")`
  with `name` / `parse`; `StoredEvent` gains `Metric` and `Module`; `StateStore` gains `module_state` and
  `put_module_state`; `SCHEMA_VERSION` is 2. `MemoryStore` keeps module state; the storage conformance suite
  checks module records, metric samples, flow notes and module state; the manager routes module kinds by name.

- Phase 0b step 4: schema v2. Migration `0002_modules.sql` for SQLite and Postgres: `events` accepts module
  record kinds and gains `module`; new `metrics` and `module_state` tables. New snapshots `sqlite/v2.db` and
  `postgres/v2_seed.sql` from `seed_v2.sql`; the v1 snapshot is unchanged. `build.sh` only writes missing
  snapshots (`--force <version>` to rebuild one); the Tests workflow loads and repeats 0002 on Postgres; both
  backends check one migration per schema version and a snapshot for each.

- Phase 0b step 5: `scribe-module-conformance`, the suite every module must pass: manifest rules, config
  errors with their line, live vs restart reloads, start / stop / start again, nothing emitted while paused,
  flow-hook time budget, random payloads without panics, only declared record kinds and metrics.
  `scribe-test-support` gains `RecordingEmitter`, `module_context`, `TagModule` (flow hook), `TicksModule`
  (metric source), `NoopModule` and `MisbehavingModule`; the suite's own tests prove it catches 7 faults.

- Phase 0b step 6: `scribe-module-url`, the URL module skeleton. Manifest (`url.request` records, read call
  `list`, needs payload), `[modules.url] query` (default `redact_values`) with the deprecated
  `privacy.url_query` still honoured and an error when both disagree; flow hook that notes the URL, records
  `url.request` and counts requests per host once the parser exists. The request parser moved here as
  `parse::request_url` (stub until phase 3) and the `http_request` fuzz target with it; `scribe-enrich` keeps
  only a `host_header` stub. `ConfigDoc::get` reads keys outside a module's section. Passes the module suite.

- Phase 0b step 7: `[modules]` in the config. `enabled = ["url"]` (default) lists the compiled-in modules to
  run (new `url` Cargo feature, on by default); each `[modules.<id>]` table is checked by its module, with the
  line in errors. Unknown, duplicate or not-built modules are errors. Sink `events` accept `metric` and module
  record kinds such as `url.request`, checked against the enabled modules. `privacy.url_query` is deprecated in
  favour of `[modules.url] query` (warning at start and in `--check-config`). `--check-config` prints each
  module's effective settings; the startup summary lists the modules; `Module::effective_config` added.

- Phase 0b step 8: `scribed` runs its modules. `ModuleHost` configures and starts the enabled modules, runs
  flow hooks within a time budget (over-budget calls counted), switches off only a module whose hook or source
  panics (health degraded), ticks sources on their interval, and pauses, resumes, reconfigures and stops them.
  Module output goes through a bounded queue (`OutputQueue`, drops counted) to the storage manager once a second;
  module state is read at start. The log shows `module url started` / `stopped`.

### Changed
- Shipped `config/scribe.toml`: the `[privacy]` table is replaced by `[modules]` and `[modules.url]`.

### Fixed
- Plan totals after the `scribe daemon` change were 0.5 day too high (121 → 120.5, 111.5 → 111, M1 59 → 58.5,
  52 → 51.5); corrected in the new totals. M1 remaining after the security update was 57 instead of 56.5;
  corrected with the module framework totals. The skill's M2 and M3 figures had not been updated; now current.
- Workspace version in `Cargo.toml` / `Cargo.lock` synced to 0.1.1 to match the `v0.1.1` tag
  (`scripts/version.sh check` failed with 0.1.0).

## [0.1.1] - 2026-11-08

First tagged version (`v0.1.1` on `5ff4049`; there is no `v0.1.0` tag). Scaffold, test infrastructure,
design documents and phase 0 (foundations).

### Added
- Rust workspace skeleton: `scribed` daemon, `scribe` CLI, core types, enrichment, sensor stubs for Linux (eBPF),
  Windows (ETW) and pcap, storage plugin interfaces with SQLite and PostgreSQL backend stubs and v1 schemas.
- Test infrastructure: `scribe-test-support` (test doubles, packet builders, pcap writer, `gen-fixtures`),
  storage and sensor conformance suites, 13 pcap fixtures, 11 daemon scenarios, raw sensor samples,
  schema snapshots, fuzz targets, UI mock API data, end-to-end scripts.
- Tag-based versioning (`scripts/version.sh`, `--version` on both binaries) and 8 GitHub workflows
  (Release and Version tracking automatic, the rest manual).
- VSCodium launch, task and editor configuration.
- Documents: implementation plan, diagrams, test approach, status report, specification;
  `scribe-conventions` skill and `CLAUDE.md`.
- Config format v1 draft `config/scribe.toml` with every option and its default.
- This changelog.
- `scribe_core::units`: config durations (`45s`, `10m`, `1h`, `7d`), sizes (`512KiB`…`2TiB`) and percentages (`5%`),
  with clear errors (e.g. `32MB` suggests `MiB`), TOML support and property tests.
- `scribe_core::platform`: default config, data and log paths per OS (Windows: next to `scribed.exe`), total RAM
  (`/proc/meminfo`, `sysctl`, `GlobalMemoryStatusEx`) and volume size / free space for percentage limits.
- Config loading in `scribe-daemon` (now a library plus the `scribed` binary): lookup order `--config`,
  `SCRIBE_CONFIG`, OS default, built-in defaults; full v1 model with errors that name file, line and column;
  cross-field checks; paths and percentages resolved for the host; effective config printable as TOML.
- `SinkConfig` carries retention and batching settings.
- Logging (`scribe_daemon::logging`): level with `SCRIBE_LOG` override, text or JSON, log file with daily or
  size rotation, journald (Linux) and unified logging (macOS); falls back to stderr with a warning.
- `scribed` runs as a long-lived process: `--config`, `--check-config` and `--version`; loads the config, starts
  logging, opens storage, waits for Ctrl-C or SIGTERM and shuts down cleanly. Exit codes 0 / 1 / 2.
- `scribe` CLI parses all commands with `clap` (`status`, `hosts`, `mode`, `alerts [ack <id>]`,
  `baseline add|rm`, `export`, `version`); everything except `version` reports "not implemented yet" (exit 1).
- Tests for the storage manager: registry kinds and roles, routing by event kind, error propagation.
- Release workflow smoke test also checks `scribed --version` and `scribed --check-config` on the shipped config.
- readme section *Running scribed*; spec v0.3, conventions skill, plan and status updated for the end of phase 0.

### Changed
- Phase 0: workspace dependencies added (tokio, serde, toml, thiserror, anyhow, clap, tracing and friends, fs4,
  libc, windows-sys, proptest, tempfile); `StorageError` and `SensorError` now use `thiserror` (messages unchanged).
- Minimum Rust version policy *follow dependencies*; minimum raised from 1.70 to 1.89.

### Fixed
- `workfiles/specs.md` sections 9.2 *Environment variables* and 9.3 *Build options*, lost in an earlier edit, restored.

### Removed
- `config/scribe.example.toml`, replaced by `config/scribe.toml`.

[Unreleased]: https://github.com/savex/scribe/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/savex/scribe/releases/tag/v0.1.1
