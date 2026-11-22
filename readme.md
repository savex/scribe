# scribe

Cross-platform (macOS, Linux, Windows) tool that logs and tracks every outgoing
connection from a host: which hosts and URLs are contacted, by which process,
how often, and whether the traffic uses TLS.

## Modes

- **learn** — record everything and build the list of known hosts; no alerts.
- **caution** — alert on unknown hosts that look unusual, and on any non-TLS traffic.
- **alert** — alert on every host or request that is not on the list.

## Layout

```
crates/
  core/                 shared types: FlowEvent, Mode, Sensor trait
  enrich/               DNS cache, TLS SNI / HTTP Host parsing, TLS detection
  sensor-linux/         eBPF sensor (Linux)
  sensor-windows/       ETW sensor (Windows)
  sensor-pcap/          libpcap / Npcap fallback (all OSes)
  storage-api/          storage plugin traits: StateStore, EventSink, StorageFactory
  storage-manager/      backend registry, fan-out to sinks
  storage-sqlite/       default backend (implemented)
  storage-postgres/     PostgreSQL backend (feature `postgres`)
  storage-conformance/  shared test suite every backend must pass
  sensor-conformance/   shared test suite every sensor must pass + traffic generator
  module-api/           interface for scribed modules (manifest, hooks, sources, outputs)
  module-url/           URL tracking module (feature `url`, on by default)
  module-conformance/   shared test suite every module must pass
  test-support/         test doubles, packet builders, fixture generator
  daemon/               `scribed` service
  cli/                  `scribe` command line client
macos/ScribeExtension/  Network Extension (Swift), planned
ui/                     optional Tauri UI, planned (mock API scenarios in ui/tests)
config/                 default configuration (scribe.toml, format v1 draft)
testdata/               pcap fixtures, daemon scenarios, raw sensor records, schema snapshots
fuzz/                   cargo-fuzz targets and seed corpus
tests/                  cross-crate smoke, integration and scenario tests (crate scribe-tests)
tests/e2e/              install / upgrade / uninstall tests per OS
workfiles/              plan, diagrams, test approach, status, specification
changelog.md            change history (Keep a Changelog format)
.claude/skills/         scribe-conventions: agreed assumptions and config values
```

Design decisions and config values are collected in
[.claude/skills/scribe-conventions/SKILL.md](.claude/skills/scribe-conventions/SKILL.md);
rules for AI assistants are in [CLAUDE.md](CLAUDE.md).

## Build

```sh
cargo build                       # SQLite backend only
cargo build --features postgres   # add PostgreSQL
cargo nextest run --workspace --all-features            # fast run (or: cargo test)
cargo nextest run --workspace -E 'binary(smoke) | test(/(^|::)smoke::/)'  # one tag: smoke, functional, integration, scenario
cargo run -p scribe-test-support --bin gen-fixtures   # regenerate testdata/pcap and fuzz seeds
```

See [workfiles/test-approach.md](workfiles/test-approach.md) for how testing is organised and
[workfiles/test-list.md](workfiles/test-list.md) for the tagged test list and its time budget.

## Running scribed

```sh
cargo run --bin scribed -- --check-config                      # print the effective config and exit
cargo run --bin scribed -- --config config/scribe.toml         # run until Ctrl-C / SIGTERM
SCRIBE_LOG=debug cargo run --bin scribed -- --config my.toml   # more logging (RUST_LOG syntax)
```

The config is found via `--config`, then `SCRIBE_CONFIG`, then the OS default
(`/etc/scribe/scribe.toml`, `/Library/Application Support/scribe/scribe.toml`, or `scribe.toml`
next to `scribed.exe`); with none, built-in defaults apply. The defaults keep data under
`/var/lib/scribe` (or the macOS / Windows equivalent) and log to `/var/log/scribe`, which needs
admin rights. For a local run, point `data_dir` at a folder you own and set `log.file = ""` to log
to the terminal:

```toml
data_dir = "/tmp/scribe"
[log]
file = ""
```

Exit codes: `0` success, `1` runtime failure, `2` usage or configuration error. Capture and
storage aren't wired up yet; scribed starts, logs its settings, starts its modules and waits.

## Modules

New functionality is added as a compiled-in module (`crates/module-*`, a Cargo feature of
`scribe-daemon`) that implements `scribe_module_api::Module` and passes
`scribe-module-conformance`. Modules attach notes to flows and emit their own records, metric
samples and state; `[modules] enabled` picks which ones run, and each reads its own
`[modules.<id>]` table. URL tracking (`url`, on by default) is the first; kernel metrics is the
example of a later one. Design: `workfiles/specs.md` section 7.4.

## Versioning

Git tags are the source of truth: `vMAJOR.MINOR.PATCH`, optionally with a pre-release
label (`v1.0.0-rc.1`). The workspace version in `Cargo.toml` always equals the latest
release tag.

- `scribe --version` / `scribed --version` print the version from the nearest tag:
  `1.2.0` on a tagged commit, `1.2.0+3.gabc1234` three commits later
  (built by `crates/core/build.rs`; release builds set it from the tag).
- [`scripts/version.sh`](scripts/version.sh) shows and checks versions
  (`current`, `latest-tag`, `next minor rc.1`, `check`, ...).

To release, run the **Bump version** workflow (choose patch / minor / major, an optional
pre-release label, or an explicit version). It commits `Release vX.Y.Z` to `main`, tags it
and starts **Release**, which builds Linux, macOS and Windows binaries and publishes a
GitHub Release. Pushing a `v*` tag by hand starts **Release** too.

## CI workflows

| Workflow | Trigger | What it does |
|---|---|---|
| Release | push of a `v*` tag (or started by Bump version) | verify tag, test, build 4 targets, publish release |
| Version tracking | every push to `main` | `Cargo.toml` vs tags, version report |
| Bump version | manual | next version, commit, tag, start Release |
| Tests | manual | fmt, clippy, minimum-Rust-version check, tests on 3 OSes, fixtures, SQLite / Postgres |
| Sensor tests | manual | privileged sensor conformance on 3 OSes |
| Fuzz | manual | cargo-fuzz on the parsers |
| UI tests | manual | Vitest + Playwright against the mock API (skips until the UI exists) |
| End-to-end | manual | install / modes / upgrade / uninstall from a release's packages |

## Status

Phases 0, 0b and 1 are done: config, logging, daemon lifecycle, CLI parsing, the module framework
with the URL module skeleton, and the SQLite backend (state and events). Sensors, the storage
manager's batching and spool, Postgres, the policy engine and the local API are not implemented yet. Details: `workfiles/status.md`.
