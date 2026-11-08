# Changelog

All notable changes to scribe are recorded here, newest first.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow the
`v*` git tags described in [readme.md](readme.md#versioning).

Every commit that changes behaviour, configuration, interfaces, tooling or documents adds a line under
**Unreleased**. On release, **Bump version** turns that section into the new version's section.

Sections: **Added**, **Changed**, **Deprecated**, **Removed**, **Fixed**, **Security**.

## [Unreleased]

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

### Changed
- Phase 0: workspace dependencies added (tokio, serde, toml, thiserror, anyhow, clap, tracing and friends, fs4,
  libc, windows-sys, proptest, tempfile); `StorageError` and `SensorError` now use `thiserror` (messages unchanged).
- Minimum Rust version policy *follow dependencies*; minimum raised from 1.70 to 1.89.

### Removed
- `config/scribe.example.toml`, replaced by `config/scribe.toml`.
