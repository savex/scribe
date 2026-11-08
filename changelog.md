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
