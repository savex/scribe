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
