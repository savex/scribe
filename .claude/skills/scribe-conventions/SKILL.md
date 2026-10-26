---
name: scribe-conventions
description: Assumptions, decisions and config values for scribe — modes and alert rules, storage roles and schema conventions, config keys, enrichment (SNI, DNS, ECH, QUIC with ring), versioning and releases, CI workflows, test doubles and test-data rules, performance targets. Use when implementing or changing any scribe module, config, migration, workflow, fixture or test.
---

# scribe conventions

The decisions, assumptions and concrete values agreed so far, collected in one place.
Use it as the reference when implementing a module, writing tests or changing CI.

- **Decided** values are already in the code, config or workflows; change them there and here together.
- **Proposed** values come from the design discussion but no code uses them yet.
- **Open** items still need a decision.

Related documents: [plan](../../../workfiles/plan.md), [diagrams](../../../workfiles/diagram.md),
[test approach](../../../workfiles/test-approach.md), [status](../../../workfiles/status.md).

---

## 1. Product scope

| Item | Value | State |
|---|---|---|
| Purpose | Log and track every outgoing connection from a host: hosts / URLs contacted, by which process, how often, with or without TLS | Decided |
| Target OS | macOS, Linux, Windows | Decided |
| Architecture | Capture layer → daemon (enrichment, counters, policy, storage, local API) → CLI and optional UI | Decided |
| UI | Optional, implemented later, talks to the daemon only through the local API | Decided |
| Blocking traffic | Out of scope for now (later: nftables, Network Extension verdicts, WFP) | Decided |
| Full URLs inside TLS | Not available without a MITM proxy; if ever added, a separate opt-in module | Decided |

## 2. Modes

| Mode | Behaviour | State |
|---|---|---|
| `learn` (default) | Record everything, add every new host to the baseline (`source = learned`), never alert | Decided |
| `caution` | Alert on hosts **not on the list that look non-ordinary**, plus **any plaintext (non-TLS) flow**, even to listed hosts | Decided |
| `alert` | Alert on every host or flow not on the list | Decided |

| Setting | Value | State |
|---|---|---|
| Default mode | `learn` | Decided (`Mode::default()`) |
| Time-limited learn mode | `learn_for` (example `7d`), then switch to `then` (example `caution`) | Proposed (scenario format) |
| Alert dedupe key | host + process path | Decided (`AlertState.key`) |
| Alert dedupe window | `10m` | Proposed (scenario default) |
| Hosts with no hostname | Tracked by IP, flagged "unresolved", never dropped | Decided (scenarios) |

**"Non-ordinary" signals for caution mode** (proposed; each rule returns a score and a reason):

| Reason id | Signal |
|---|---|
| `raw_ip` | Connection to an IP with no preceding DNS lookup |
| `unusual_port` | Port outside the usual set (e.g. 80/443/53) |
| `high_entropy` | Random-looking / DGA-style domain labels |
| `new_tld` | Top-level domain not seen before |
| `new_process` | Process that never made network connections before |
| `threat_list` | Host on a threat list |
| `unlisted_host` | Host not on the baseline (used by `alert` mode) |
| `plaintext` | Non-TLS flow (used by `caution` and `alert`) |

Open: exact scores, the alert threshold, the "usual ports" list and where threat lists come from.

## 3. Language, toolchain and code conventions

| Item | Value | State |
|---|---|---|
| Core language | Rust (edition 2021) | Decided |
| Minimum Rust version | 1.70 (`rust-version` in `Cargo.toml`; checked by the Tests workflow) | Decided |
| Development toolchain | current stable | Decided |
| macOS capture piece | Swift System Extension (`NEFilterDataProvider`) talking to the daemon over XPC | Decided |
| Windows capture | ETW from user mode first; WFP driver / WinDivert only for later blocking | Decided |
| Linux capture | eBPF with `aya`; kernel 5.8+, CO-RE; pcap fallback on older kernels | Decided (code is a stub) |
| Fallback capture | libpcap (Linux, macOS) / Npcap (Windows), no process attribution | Decided |
| UI technology | Tauri | Proposed |
| Crypto library | `ring` 0.17 — HKDF, AES-128-GCM and QUIC header protection (`ring::aead::quic`) for QUIC Initial decryption; most downloaded option (839M total, 197M in 90 days on crates.io, 2026-10-26) and needs Rust 1.66 | Decided |
| Async in interfaces | Boxed futures (`BoxFuture`), no `async-trait` crate | Decided |
| External dependencies | None yet; skeleton builds offline | Decided (until implementation starts) |
| Formatting / lint | `cargo fmt`; `cargo clippy -- -D warnings` must pass | Decided |
| Line endings | LF everywhere (`.gitattributes`), binary fixtures marked binary | Decided |
| Time in production code | Read through the `Clock` interface so tests can control it | Decided |

**Planned libraries** (proposed, add when implementing): `tokio`, `serde`, `toml`, `tracing`,
`thiserror`, `rusqlite` (bundled), `tokio-postgres` + `deadpool`, `aya`, `windows`, `pcap`,
`tonic` (gRPC), `proptest`, `libfuzzer-sys`, `ring` 0.17 (decided, see table above).

## 4. Crates and binaries

| Name | Kind | Purpose |
|---|---|---|
| `scribe-core` | lib | Flow events, modes, alerts, clock, sensor interface, `VERSION` |
| `scribe-enrich` | lib | DNS cache, TLS SNI, HTTP Host, TLS detection |
| `scribe-sensor-linux` / `-windows` / `-pcap` | lib | Capture sensors |
| `scribe-storage-api` | lib | `StateStore`, `EventSink`, `StorageFactory` |
| `scribe-storage-manager` | lib | Registry, fan-out to sinks (later: cache, batching, spool, retention) |
| `scribe-storage-sqlite` | lib | Default backend (feature `sqlite`, on by default) |
| `scribe-storage-postgres` | lib | Optional backend (feature `postgres`) |
| `scribe-storage-conformance` / `scribe-sensor-conformance` | lib | Shared test suites |
| `scribe-test-support` | lib + bin | Test doubles, packet builders, `gen-fixtures` |
| `scribed` | bin (crate `scribe-daemon`) | The service |
| `scribe` | bin (crate `scribe-cli`) | The command line client |

Only SQLite and Postgres storage backends are in scope. ClickHouse, OpenSearch, file sinks and
external gRPC storage plugins were discussed and **deliberately left out**.

## 5. Storage

| Item | Value | State |
|---|---|---|
| Roles | Exactly one **state store** (hosts, counters, baselines, alert state); zero or more **event sinks** (flow / alert / audit records) | Decided |
| Backend selection | `kind = "sqlite"` / `"postgres"` in config, resolved by the registry | Decided |
| Counter updates | Always as deltas (`n = n + excluded.n`), never read-modify-write | Decided |
| Security flags | `tls_seen` / `plaintext_seen` only ever turn on | Decided |
| Record schema version | `SCHEMA_VERSION = 1` | Decided |
| SQLite timestamps | Unix epoch **milliseconds** (INTEGER); booleans as 0/1 | Decided |
| Postgres types | `TIMESTAMPTZ`, `BOOLEAN`, `INET`, `JSONB` payloads | Decided |
| Event payloads | JSON text (SQLite) / JSONB (Postgres) | Decided |
| SQLite `max_batch` | 1000 | Decided |
| Postgres `max_batch` | 5000 | Decided |
| Sink write batching | Flush at 500 events or 1 s, per sink, in its own task | Proposed |
| Host cache | In-memory LRU in front of the state store | Proposed (size open) |
| Spool | Local append-only file, replayed in order when a sink recovers; oldest dropped at the size cap, drops counted | Proposed (size cap open) |
| Retention | Per sink, e.g. `30d`; enforced by the manager when the backend can't | Proposed |
| Credentials | OS keychain (macOS), DPAPI (Windows), Secret Service (Linux) or a root-only file; never plain config | Proposed |
| Migrations | Files in `crates/storage-*/migrations/`, idempotent (`IF NOT EXISTS`); a snapshot per released schema in `testdata/db/`, never edited afterwards | Decided |

## 6. Configuration (`scribed`)

Example in [config/scribe.example.toml](../../../config/scribe.example.toml). Config loading is not implemented yet.

| Key | Default / example | State |
|---|---|---|
| `mode` | `"learn"` | Decided |
| `profile` | `"default"` | Decided |
| `[storage.state] kind` | `"sqlite"` | Decided |
| `[storage.state] path` | `/var/lib/scribe/state.db` | Proposed |
| `[[storage.sinks]] name` | `"local-history"` | Proposed |
| `[[storage.sinks]] path` | `/var/lib/scribe/events.db` | Proposed |
| `[[storage.sinks]] retention` | `"30d"` | Proposed |
| `[[storage.sinks]] events` | all kinds when empty; else any of `flow`, `alert`, `audit` | Decided (`SinkConfig.accepts`) |
| Postgres `url` | connection string **without** password | Decided |
| Postgres `credentials` | secret reference, e.g. `keychain:scribe-postgres` | Proposed |

Open: Windows and macOS data paths, config file location per OS, log location and level.

## 7. Enrichment

| Item | Value | State |
|---|---|---|
| Hostname sources, in priority | TLS SNI → HTTP `Host` header → DNS cache (IP → queried name) | Decided (fixtures, scenarios) |
| DNS cache | Keyed by IP, honours record TTL; CNAME chains map back to the **queried** name | Decided |
| TLS detection | First bytes `0x16 0x03 ..` = TLS; empty = unknown; anything else = plaintext; never by port | Decided |
| ECH | Only the outer public name is visible; flagged `ech: true` | Decided (fixtures) |
| DNS-over-HTTPS | Later lookups are invisible; flows fall back to IP | Decided |
| QUIC | SNI from the Initial packet: derive keys from the Destination Connection ID and the version salt (HKDF-SHA256), remove header protection (AES-128-ECB), decrypt (AES-128-GCM), reassemble CRYPTO frames by offset, then parse the ClientHello | Proposed (parser and fixture not written) |
| QUIC crypto | `ring` 0.17 in `enrich` and `test-support`; fixture checked against the RFC 9001 Appendix A sample packet | Decided |
| Full URL | Plaintext HTTP only | Decided |

## 8. Counting

Three counters per host and per process + host, plus time buckets (hourly proposed):

- **Connections / flows:** each TCP connection or UDP / QUIC flow.
- **Requests:** plaintext HTTP requests only (not visible inside TLS).
- **Bytes out.**

## 9. Local API, CLI and services

| Item | Value | State |
|---|---|---|
| Local API | gRPC (`tonic`) over a Unix socket (Linux, macOS) or named pipe (Windows) | Proposed |
| API access | Socket readable only by the owner and the admin group | Proposed |
| CLI commands | `status`, `hosts`, `mode <learn\|caution\|alert>`, `alerts`, `alerts ack`, `baseline add/rm`, `export`, `version` / `--version` | Partly decided (`version`, mode parsing exist) |
| Linux service | systemd unit `scribed` | Proposed (used by e2e script) |
| macOS service | launchd `com.scribe.daemon`; uninstaller `/Library/Application Support/scribe/uninstall.sh` | Proposed (used by e2e script) |
| Windows service | `scribed` | Proposed (used by e2e script) |
| Privileges | Runs as root / SYSTEM, drops privileges after the sensor starts | Proposed |

## 10. Versioning and releases

| Item | Value | State |
|---|---|---|
| Source of truth | Git tags `vMAJOR.MINOR.PATCH[-PRERELEASE]` | Decided |
| `Cargo.toml` version | Always equals the latest release tag | Decided |
| Binary version | `1.2.0` on a tag, `1.2.0+3.gabc1234` after 3 commits, `<cargo>+g<sha>` with no tag; no dirty marker | Decided (`crates/core/build.rs`) |
| Override | `SCRIBE_VERSION` env var (release builds) | Decided |
| Bump after a pre-release | Same-level bump finalizes it (`2.0.0-rc.1` + major → `2.0.0`) | Decided (`scripts/version.sh`) |
| First release | Run **Bump version** with `minor` → `v0.1.0` | Decided |
| Releases come from | Tags on `main` only | Decided |
| Release targets | `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc` | Decided |
| Release assets | `scribe-<version>-<target>.tar.gz` (`.zip` on Windows) + `SHA256SUMS` | Decided |
| Installers | `.deb`, `.rpm`, MSI (WiX), notarized `.pkg` | Proposed (plan phase 13) |

## 11. CI workflows

| Workflow | Trigger | State |
|---|---|---|
| Release | push of a `v*` tag, or dispatched by Bump version | Decided — automatic |
| Version tracking | every push to `main` | Decided — automatic |
| Bump version, Tests, Sensor tests, Fuzz, UI tests, End-to-end | manual (`workflow_dispatch`) | Decided — manual |

Notes:
- Bump version starts Release itself, because pushes made with `GITHUB_TOKEN` don't trigger other workflows.
- Bump version pushes straight to `main`; it fails if `main` requires pull requests.
- No scheduled (nightly) runs; the user chose manual triggers.

## 12. Testing

| Item | Value | State |
|---|---|---|
| Test levels | unit, isolated component, contract / conformance, integration, end-to-end, non-functional | Decided |
| Test doubles | `FakeSensor`, `FakeClock`, `MemoryStore`, `MemorySink`, `FaultySink`, `RecordingAlertSink`; `MockApiServer` planned | Decided |
| New storage backend | Must pass the storage conformance suite before it is registered | Decided |
| New sensor | Must pass the sensor conformance suite | Decided |
| Sensor event deadline | Each expected event within **1 s** | Decided (`SuiteOptions`) |
| Local test server timeout | **5 s** | Decided |
| Postgres test DB | `postgres://scribe:scribe@localhost:5432/scribe_test` (`SCRIBE_TEST_POSTGRES_URL`), `postgres:16` in CI | Decided |
| Fuzz run time | 1800 s per target | Decided (workflow default) |
| Linux kernel matrix | 5.8, 5.15, 6.1, latest (virtme-ng / lvh) | Proposed |
| Coverage targets | ≥ 80% for `core`, `enrich`, `storage-*`, policy engine; ≥ 60% overall | Proposed |
| CI time budgets | every-PR stage < 15 min, nightly-equivalent < 2 h, pre-release 1–2 days | Proposed |
| Release exit criteria | all scenarios and sensor conformance pass on every OS; no open crash / data-loss bugs; 7 crash-free fuzz runs in a row | Proposed |

**Test data conventions** (decided):
- Addresses only from documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`; client `10.0.0.2` / `fd00::2`.
- Names under `example.com` / `example.net`. The one exception is `doh`, which uses `8.8.8.8` / `dns.google`.
- Fixture base time `1_700_000_000` (2023-11-14T22:13:20Z), one pcap frame per millisecond; `FakeClock::default()` uses the same time.
- Fixture MACs: client `02:00:00:00:00:02`, gateway `02:00:00:00:00:01`.
- `testdata/pcap/` and `fuzz/corpus/` are generated by `gen-fixtures` and checked by `fixtures_up_to_date`; never edit them by hand.
- Never commit traffic captured from a real user. Every bug fix adds a fixture or scenario.

## 13. Non-functional targets (proposed)

| Item | Target |
|---|---|
| Throughput | 1,000 new connections/s |
| Daemon CPU | < 2% of one core at that rate |
| Daemon memory | < 100 MB |
| Event → database latency | p99 < 1 s |
| Soak | 24 h mixed traffic: flat memory, no handle leaks, empty spool |

## 14. Planning assumptions

| Item | Value |
|---|---|
| Estimates assume | one experienced Rust developer; LOC without blanks and comments; tests counted separately |
| Total size | ~13,500 production LOC + ~3,600 test LOC |
| Total effort | 90–117 person-days, 110–140 with a 20% buffer |
| Milestones | M1 MVP (pcap, SQLite, modes, CLI) 43–55 days; M2 native sensors 32–42 days; M3 production 15–20 days |
| Main risks | Apple Network Extension entitlement and notarization lead time; eBPF kernel variance; Npcap needed for Windows payloads; DoH / ECH hide hostnames; caution-mode tuning |

## 15. Development environment

| Item | Value |
|---|---|
| Editor | VSCodium with rust-analyzer (Testing panel on), CodeLLDB, Even Better TOML, YAML, GitHub Actions, ShellCheck, PowerShell (all from Open VSX) |
| Tracked editor files | `.vscode/settings.json`, `launch.json`, `tasks.json`, `extensions.json` only |
| Local CI equivalent | Task "ci: Tests workflow (local)" |
| Coverage locally | rustup `llvm-tools` + `-C instrument-coverage` (no `cargo-llvm-cov` installed) |
