# scribe readiness by module

As of commit `37e1d3f` (2026-10-26), scribe is not usable yet. It doesn't capture traffic, store anything, or apply the modes. What exists is the structure (interfaces, schemas, configuration), complete test infrastructure, and CI with versioning.

**How this was measured**
- **Completion** is an estimate against each module's scope in [plan.md](plan.md).
- **Coverage** is line coverage from `cargo test --workspace --all-features` alone, measured with LLVM source-based coverage (rustup `llvm-tools`) on macOS. 14 tests passed and 6 were skipped.

## Product modules

| Module | Plan phase | Completion | What exists | What's missing | Test coverage |
|---|---|---|---|---|---|
| `core` | 0 | **~70%** | Flow event, the three modes, sensor interface, clock, alert interface, tag-based `VERSION` | Config model and loading, logging, shared error types | **0%** (0/27). Mode parsing has no test. |
| `storage-api` | 1–2 | **~85%** | State store and event sink interfaces, backend factory, data model, capability flags, errors | Payload serialization (serde), schema version on records | **21%** (9/42). Only reached through the test doubles. |
| `storage-manager` | 2 | **~15%** | Backend registry chosen by Cargo feature, config types, sending events to each sink in turn | Host cache, per-sink batching tasks, spool and replay, retention, health | **0%** (0/104) |
| `storage-sqlite` | 1 | **~10%** | v1 schema, factory, option checks; every method is a stub returning "not implemented" | All of it (rusqlite, migration runner, queries) | **0%** (0/99). Conformance tests exist but are skipped. |
| `storage-postgres` | 12 | **~10%** | v1 schema, factory, stubs | All of it (tokio-postgres, connection pool, migrations) | **0%** (0/101). Conformance tests skipped. |
| `enrich` | 3 | **~10%** | TLS / plaintext detection, DNS cache | SNI parsing, HTTP parsing, DNS answer parser, QUIC | **38%** (16/42). TLS detection 84%; DNS cache and HTTP 0%. |
| Policy engine | 4 | **0%** | No crate yet. 11 scenario files are ready. | Rules, scoring, dedupe, mode switching | n/a |
| `daemon` (`scribed`) | 5 | **~5%** | Prints version, mode, sensor and storage backends | The whole pipeline, service integration, dropping privileges | **0%** (0/20) |
| `sensor-pcap` | 6 | **~2%** | Stub that implements the sensor interface | Capture and flow reassembly | **0%** (0/10). Its conformance test is skipped. |
| `sensor-linux` (eBPF) | 7 | **~2%** | Stub, compiled only on Linux | eBPF programs, loader, process lookup | n/a (not built on macOS) |
| `sensor-windows` (ETW) | 8 | **~2%** | Stub, compiled only on Windows | ETW session, DNS-client events, Npcap | n/a (not built on macOS) |
| macOS Network Extension | 9 | **0%** | README only | Swift extension, XPC bridge | n/a |
| Local API and `cli` | 10 | **~10%** | CLI argument parsing, `--version`, mode name checking | gRPC API; the CLI's commands talk to nothing | **0%** (0/23) |
| Alert outputs | 11 | **~5%** | Alert output interface | Notifications, log, webhook | n/a |
| UI (Tauri) | later | **0%** | Test folders and 7 mock API data files | Everything | n/a |
| Packaging | 13 | **~15%** | Release workflow builds archives for 4 targets with checksums | `.deb` / `.rpm`, MSI, notarized `.pkg`, signing | n/a |

**Product total:** about 470 measurable lines, 25 covered by tests (**5.3%**). All 25 are in `enrich` and `storage-api`.

## Test infrastructure, CI and data

These are finished for the current scope.

| Module | Completion | What exists | Test coverage |
|---|---|---|---|
| `test-support` | **100%** | Test doubles, packet builders, pcap writer, fixture generator | **85%** (866/1020) |
| `storage-conformance` | **100%** | Test suite every storage backend must pass | **98%** (215/220) |
| `sensor-conformance` | **100%** | Test suite every sensor must pass, plus the traffic generator | **46%** (87/190). The generator is 92% covered; the suite runner needs a real sensor. |
| Test data | **100%** | 13 pcap fixtures with expected results, 11 scenarios, raw sensor samples, v1 database snapshots | Checked by the fixture test |
| Fuzzing | **~30%** | 2 targets with seeds; DNS and QUIC targets wait for those parsers | Never run (needs Rust nightly) |
| End-to-end scripts | **100% scripted** | Scripts for Linux, macOS and Windows | Never run (needs installers and CLI commands) |
| CI and versioning | **~90%** | 8 workflows, `version.sh`, version from tags | Run locally only, not on GitHub |

## What this means

- **Plan progress:** phase 0 (foundations) is about 70% done. Configuration loading and logging are what's left. Phases 1–14 are at 0–15%.
- **Production code:** roughly 500 of the planned 13,500 lines exist, about 4%, and much of that is interface definitions and stubs.
- **Coverage looks better than it is:** overall line coverage is 67%, but that number is almost all test infrastructure. For the product code it is 5%.
- **Tests are written before the code:** the conformance tests and fixtures already exist. The SQLite backend and the parsers in `enrich` turn existing skipped tests and fixtures into real coverage as soon as they're implemented.
- **Most effective next steps**, following plan milestone M1:
  1. The SQLite backend: its conformance tests are already written.
  2. The SNI, HTTP and DNS parsers in `enrich`: 13 pcap fixtures with expected results are waiting.
  3. The policy engine: 11 scenarios are waiting.
- **Gaps to close now:** `core`, `storage-manager`, `cli` and `daemon` have no tests at all, and each needs only a few small unit tests to start.
