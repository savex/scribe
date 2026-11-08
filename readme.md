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
  storage-sqlite/       default backend
  storage-postgres/     PostgreSQL backend (feature `postgres`)
  storage-conformance/  shared test suite every backend must pass
  sensor-conformance/   shared test suite every sensor must pass + traffic generator
  test-support/         test doubles, packet builders, fixture generator
  daemon/               `scribed` service
  cli/                  `scribe` command line client
macos/ScribeExtension/  Network Extension (Swift), planned
ui/                     optional Tauri UI, planned (mock API scenarios in ui/tests)
config/                 default configuration (scribe.toml, format v1 draft)
testdata/               pcap fixtures, daemon scenarios, raw sensor records, schema snapshots
fuzz/                   cargo-fuzz targets and seed corpus
tests/e2e/              install / upgrade / uninstall tests per OS
workfiles/              plan, diagrams, test approach, status
.claude/skills/         scribe-conventions: agreed assumptions and config values
```

Design decisions and config values are collected in
[.claude/skills/scribe-conventions/SKILL.md](.claude/skills/scribe-conventions/SKILL.md);
rules for AI assistants are in [CLAUDE.md](CLAUDE.md).

## Build

```sh
cargo build                       # SQLite backend only
cargo build --features postgres   # add PostgreSQL
cargo test
cargo run -p scribe-test-support --bin gen-fixtures   # regenerate testdata/pcap and fuzz seeds
```

See [workfiles/test-approach.md](workfiles/test-approach.md) for how testing is organised.

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

Skeleton. Interfaces and the storage conformance suite are in place; sensors,
storage backends, the policy engine and the local API are not implemented yet.
