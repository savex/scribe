# Test approach for scribe

*Last updated 2026-11-22, after phase 1. "Implemented" marks tests that exist; everything else is the plan for
the phase named. Coverage and counts: [status.md](status.md). The catalogue of fast tests, their tags
(`smoke`, `functional`, `integration`, `scenario`), isolation rules and the 1–2 minute budget:
[test-list.md](test-list.md).*

## 1. Goals

- Prove that every outgoing connection is seen, attributed to the right host and process, counted correctly, and stored.
- Prove that each mode (learn, caution, alert) raises exactly the alerts it should, no more and no fewer.
- Let each layer (UI, capture, daemon, storage) be tested **without the others**, so most tests run fast, need no root rights, and run on every pull request.
- Keep privileged tests and tests that depend on a specific OS few, scripted, and run on dedicated CI machines.

## 2. Test levels

| Level | What it covers | Privileges | When it runs |
|---|---|---|---|
| **Unit** | Functions and modules: parsers, scoring rules, config, mode logic | none | every run |
| **Isolated component** | One layer with all its neighbours replaced by test doubles (sections 4–7a) | none* | every run |
| **Contract / conformance** | Every implementation of a shared interface passes the same suite: storage, sensor and module conformance (all three exist) | backend-dependent | every run / privileged stage |
| **Integration** | Real daemon + real sensor + real storage on one OS | root / admin | privileged stage |
| **End-to-end** | Installed package, real traffic, CLI / UI checks | root / admin | before release |
| **Non-functional** | Performance, long-running soak, fuzzing, security | mixed | privileged stage / before release |

\* Except the privileged capture tests in section 5.2.

**When tests run.** All test workflows are started by hand (decision in the plan); only Release and
Version tracking run automatically. "Every run" means every run of the Tests workflow and every local
pre-commit check; the "privileged stage" is the Sensor tests, Fuzz and End-to-end workflows, also
started by hand. Section 11 lists what each one runs.

## 3. How isolation works

The code already has clear boundaries between layers. Each boundary gets a test double:

| Boundary | Real implementation | Test double | Lives in |
|---|---|---|---|
| `Sensor` trait → `Observation` channel (event + first client bytes) | eBPF, ETW, Network Extension, pcap | `FakeSensor` (replays observations on every start); `flow()` builder with `http_get`, `payload`, `observe` | `crates/test-support` (implemented) |
| `StateStore` / `EventSink` | SQLite, Postgres | `MemoryStore`, `MemorySink` (module state and all event kinds), `FaultySink` (fails or slows down on command) | `crates/test-support` (implemented) |
| Modules | URL module, later modules | `TagModule` (flow hook), `TicksModule` (metric source), `NoopModule`, `MisbehavingModule` (7 faults), `RecordingEmitter`, `module_context()` | `crates/test-support` (implemented) |
| Alert outputs | OS notifications, log, webhook | `RecordingAlertSink` | `crates/test-support` (implemented) |
| Time | system clock | `FakeClock` (moved forward by the test) | `crates/test-support` (implemented) |
| Host facts | RAM and volume sizes | `FakeHost` / `BrokenHost` (`SystemFacts`) | `crates/daemon/src/config/tests.rs` (implemented) |
| Local API (gRPC) | `scribed` | `MockApiServer` built from the same `.proto` | `crates/test-support` + `ui/tests/mocks` (mock data exists; server in phase 10) |

**Rule:** production code reads time, randomness, the network and storage only through interfaces like these, so tests never need to sleep or touch real system resources.

## 4. UI — isolated tests

The UI talks to the daemon **only through the local API**, so it is tested against a mock API and never needs a running daemon or capture.

| Layer | Tool | What is tested |
|---|---|---|
| Frontend components | Vitest + Testing Library | Host table, counters, mode switch, alert list, empty/error/loading states |
| Tauri commands (Rust side) | `cargo test` with a fake API client | Requests sent correctly; API errors shown as user messages |
| Screen flows | Playwright against `MockApiServer` | Switch mode, add a host to the list from an alert, acknowledge an alert, filter and search hosts |
| Visual checks | Playwright screenshots | Light/dark theme, narrow window, long host names |
| Desktop smoke test | `tauri-driver` (WebDriver) on Linux and Windows | App starts, connects to the mock API, shows data |

**Scenarios the mock API must be able to play back:**
- Daemon not running / connection refused
- Empty database (first launch in learn mode)
- 10,000+ hosts (scrolling and paging)
- A burst of alerts (100 per second)
- Daemon restart while the UI is open
- API version mismatch

**Limitation:** WebDriver doesn't work with the macOS WebView. On macOS, only frontend tests run against the mock; the desktop smoke test is manual.

## 5. Capture layer — isolated tests

Each sensor has two parts with different test needs: **decoding** (pure functions) and **OS hookup** (needs privileges).

### 5.1 Decoding (no privileges, every run)

- Turning raw bytes into a `FlowEvent` is kept in plain functions with no OS calls.
- **Inputs:** recorded `.pcap` files and raw eBPF / ETW / Network Extension records in `testdata/`; each raw
  sample lists the `Observation`s the decoder must produce (with the client bytes as a pcap segment) and
  what enrichment and modules add.
- **Check:** output `FlowEvent`s match expected JSON (golden files).
- **Fixtures** (14 exist in `testdata/pcap/`, generated by `gen-fixtures`; expected flows carry `notes.url`
  where the URL module applies, `ech`, and `kind` (`new_flow` or `payload`)):
  - TCP + TLS 1.2 and 1.3 ClientHello with SNI, IPv4 and IPv6 — exist
  - TLS without SNI, with ECH — exist
  - Plaintext HTTP/1.1 with Host header — exists (`http_plain`); two requests on one kept-alive connection — exists (`http_keepalive`)
  - DNS A / AAAA / CNAME chains, DNS-over-HTTPS (resolver `doh.example.net` at 198.51.100.53) — exist
  - Fragmented, out-of-order, truncated and malformed packets, raw IP on an odd port — exist
  - QUIC Initial packet — **missing**; added in phase 3 and checked against RFC 9001 Appendix A
- **Enrichment tests (`crates/enrich`):** the same fixtures, plus DNS cache expiry tests using `FakeClock`.
- **Fuzzing:** `cargo-fuzz` targets for the DNS, TLS ClientHello, HTTP and QUIC parsers. They must never crash or hang.
  Two exist (`tls_client_hello`, `http_request` → `scribe_module_url::parse::request_url`); DNS and QUIC
  targets come with their parsers in phase 3. None has run yet (needs Rust nightly).

### 5.2 OS hookup (privileged stage)

The same **sensor conformance suite** (`crates/sensor-conformance`, implemented; needs a real sensor) runs against every sensor:

1. Start local test servers: TLS (self-signed cert), plain HTTP, UDP echo, QUIC, DNS.
2. Start the sensor.
3. Make known connections from a known test process.
4. Check that the sensor emits the expected observations: destination, port, process ID and path, hostname, TLS/plaintext/QUIC, byte counts, and for TCP the first client bytes in some observation (at least the first segment). Each must arrive within 1 second, with nothing missing and nothing duplicated.
5. Planned: stop, then start again (hibernation and wakeup need it); `FakeSensor` already supports it.

| Sensor | Environment | Notes |
|---|---|---|
| Linux eBPF | Network namespace in a VM; kernels 5.8, 5.15, 6.1, latest (via `virtme-ng` or `lvh`) | Also checks that loading falls back to pcap on kernels that are too old |
| Windows ETW | GitHub Windows runner, run as admin | Npcap installed silently for the packet-content tests |
| macOS Network Extension | Self-hosted Mac with an MDM profile that pre-approves the extension | Swift flow-mapping logic is unit-tested with XCTest and mocked `NEFilterFlow` objects; the XPC bridge is tested against a fake extension process, which needs no approval |
| pcap fallback | Linux / macOS / Windows runners | Same suite, but process attribution is expected to be empty |

## 6. Daemon — isolated tests

Run the real pipeline (ingest → enrichment → modules → counters → policy → storage manager) in-process with:
- `FakeSensor` instead of a real sensor
- `MemoryStore` and `MemorySink` instead of real databases
- `RecordingAlertSink` instead of notifications
- `FakeClock` instead of system time
- the real `ModuleHost` with the built-in modules, or test modules from `crates/test-support`

Until the local API exists (phase 10), scenarios drive the pipeline in-process; the scenario runner arrives
with the policy engine (phase 4) and the pipeline with phase 5. From phase 10 the same scenarios also run
through the real local API.

**Scenario files:** each scenario is a YAML file in `testdata/scenarios/` (19 today; format in its README) containing:
- mode and starting baseline
- a script of flow events
- the expected alerts, hosts and counters

The test runner loads the scenario, plays the events through the pipeline, and compares the final state to the expected one.

| Area | Scenarios |
|---|---|
| Learn mode | New hosts are added to the baseline; no alerts; switches automatically to the next mode when learn time ends |
| Caution mode | New ordinary host → no alert; raw IP with no DNS → alert; unusual port alone (30) → no alert, with a new process (55) → alert; new TLD + new process (45) → no alert; high-entropy domain → alert; threat list → alert; plaintext to a **known** host → alert with its URL note; TLS to a known host → nothing |
| Alert mode | Every host not on the list → alert; listed host over TLS → nothing |
| Alert dedupe | Same host + process within the window → one alert; after the window → new alert; acknowledged → silent (`alert-dedupe-window`, `alert-acknowledged`) |
| Counters | N connections, M requests, B bytes per host and per process + host are exact; concurrent flows to the same host |
| Hostname | Host from SNI beats DNS cache; expired DNS entry → shown as an IP; ECH outer name or no name → flagged `unresolved`; DoH resolver tracked by name |
| API | Change mode, add/remove baseline entries, list hosts, page through results, read health |
| Robustness | Slow sink doesn't slow capture; storage outage → events spooled, then replayed; full queue → drops are counted, not crashes |
| Lifecycle | Restart keeps hosts, counters, baseline and mode; config reload; clean shutdown flushes all sinks |
| Daemon commands | `status` shows run state, counters and critical metrics; `health` exits 0 / 1 with reasons; `reset` clears runtime counters and caches without touching stored history and rejects a bad config; `hibernate` is capped by `daemon.max_hibernate`, raises an alert and records nothing; `wakeup` resumes with the same mode, baseline and caches (specs 6.2.1, 8.5) |
| Modules | Notes reach stored flows and alerts; module records and metrics reach subscribed sinks only; a failing module leaves the pipeline running (section 7a) |

**Implemented daemon tests today:**
- `crates/daemon/src/config/tests.rs` — the shipped file equals the built-in defaults, a table of bad configs
  with their line, module sections, deprecated keys, resolved limits and the effective config.
- `crates/daemon/tests/scribed.rs` — the real binary: `--version`, `--check-config`, bad configs, `SCRIBE_CONFIG`,
  usage errors, unknown modules, and a run that creates `state.db` / `events.db`, starts the URL module and
  stops cleanly on SIGTERM.
- `crates/daemon/tests/module_host.rs` — the module host (section 7a).

**Service integration** (systemd, launchd, Windows Service Control Manager: start, stop, restart, privilege drop) is checked in the packaging stage, not here.

## 7. Storage — isolated tests

| Test | How | When |
|---|---|---|
| **Conformance suite** (`crates/storage-conformance`) | The same suite runs against `MemoryStore`, SQLite and Postgres; covers module records, metric samples, flow notes and module state. **Implemented** for `MemoryStore` and SQLite; Postgres in phase 12 | every run |
| SQLite | **Implemented:** fresh temporary file per test; ordering, literal filters, first / last seen, IP expiry and module state with `FakeClock`, reopening, time windows, a bad batch rolled back, state and sink sharing one file (`crates/storage-sqlite/tests/`). **Missing:** an in-memory database variant | every run |
| Postgres | Postgres service container in the Tests workflow (`SCRIBE_TEST_POSTGRES_URL`), a fresh database per run; today it loads migrations 0001 and 0002 twice and both seeds | every run (phase 12 for the backend) |
| Migrations | **Implemented for SQLite:** each released snapshot (`testdata/db/sqlite/v1.db`, `v2.db`) migrates to the latest schema and its rows read back (v1 flows as `notes.url`); a second `migrate` changes nothing; a newer schema is refused; one migration and one snapshot per schema version | every run |
| Property tests (`proptest`) | Random sequences of host updates: stored counters equal the sum of the updates; flags only turn on, never off. **Missing** (proptest is used only in `core` today); add with phase 2 | every run |
| Concurrency | Many tasks update the same host at once, including over two connections to one SQLite file; no lost updates, no `database is locked` within the busy timeout. **Missing**; add with phase 2 | every run |
| Failure injection | `FaultySink` / a broken connection / disk full: errors reported, no corruption, manager spools. Routing errors implemented; spool and disk-full in phase 2 | every run |
| Storage manager | With `MemoryStore` + `FaultySink`: batching by size and time, a failing sink doesn't affect others, spool replays in order, retention removes old events. **Implemented:** registry, routing by kind (module kinds included), error propagation, SQLite end to end. The rest in phase 2 | every run |
| Volume | 10M events, 100k hosts: write rate, query time, database size | privileged stage / before release |

**Adding a new storage backend:** it must pass the whole conformance suite before it can be registered in `Registry::with_builtin`.

## 7a. Modules — isolated tests

| Test | How | When |
|---|---|---|
| **Conformance suite** (`crates/module-conformance`, implemented) | Every module: manifest rules; config errors with line numbers; reload live vs needs-restart; start, stop and start again; nothing emitted while paused; flow-hook time budget; 500 random payloads without panics; only declared record kinds, schemas and metrics. Its own tests prove it catches 7 injected faults (`MisbehavingModule`). Refusing undeclared API calls is checked with the API (phase 10) | every run |
| URL module | Implemented: conformance, config (new and deprecated key). Phase 3: `http_plain` and other plaintext fixtures through the flow hook, the URL privacy table (specs 12.2) for every `query` value, request parser fuzzed (`http_request` target) | every run |
| Isolation (NFR-20) | Implemented in `crates/daemon/tests/module_host.rs`: a panicking module is switched off while others run, slow calls are counted, a full output queue drops and counts | every run |
| Storage | Implemented: storage conformance cases for module records, metric samples, flow notes and module state; migrations and v2 snapshots in step with `SCHEMA_VERSION`. The SQLite backend migrates both released snapshots to the latest schema and reads their rows (`crates/storage-sqlite/tests/schema.rs`, `sink.rs`) | every run |
| Daemon | Implemented: `ModuleHost` pause, resume, reconfigure, stop and source schedules with `FakeClock`; `scribed` logs module start and stop. Phase 5: `hibernate`, `wakeup` and `reset --config` drive them; phase 10: `daemon status` shows each module | every run |
| Kernel probes | Modules that use `ProbeHost` run in the privileged sensor stage (section 5.2) | privileged stage |

**Adding a new module:** it must pass the whole module conformance suite before it is added to `scribe_daemon::modules::builtin()`.

## 8. Integration and end-to-end tests

- **Integration (privileged stage, per OS; from phase 6):** the real daemon with the real sensor and SQLite, in a VM. A traffic generator makes scripted connections, and the test checks the result through the CLI (`scribe hosts`, `scribe status`).
- **End-to-end (before release):** `tests/e2e/` scripts per OS, against lab servers only (`traffic.env`
  must be filled in; empty targets stop the run):
  1. Install the **previous** release, learn the lab traffic, switch to caution.
  2. Upgrade to the new package; hosts, baseline and mode survive, the schema migrates, the installed
     config passes `--check-config`, the URL module runs.
  3. Security: groups, file modes, socket directory, hardened service unit.
  4. Caution and alert mode alerts (plaintext alerts carry the URL); `hibernate`, `wakeup`, `reset`.
  5. Uninstall: service and binaries gone, data kept unless purged.
  Checks read `--json` output and poll with a timeout instead of sleeping.

## 9. Non-functional tests

| Type | Target |
|---|---|
| Performance | 1,000 new connections/s: < 2% CPU on one core and < 100 MB memory for the daemon; event-to-database latency p99 < 1 s |
| Soak | 24 h of mixed traffic: memory stays flat, no file handle leaks, spool stays empty |
| Fuzzing | All parsers fuzzed for 30 min per Fuzz workflow run; any crash found becomes a fixture |
| Security | Daemon drops privileges after the sensor starts; every control call is refused (and audited) for a read-only peer and accepted for `scribe-admin`; the CLI refuses a fake server (socket not owned by root, pipe server not SYSTEM); oversized messages, slow calls and too many streams are cut off; startup refused for group / other-writable config, `data_dir` or `file:` credentials; `hibernate` is capped and alerts (`FakeClock`); Postgres `sslmode=disable` / `prefer` rejected off loopback, sink works against a TLS-only Postgres; webhook signatures match test vectors; a threat list with a wrong checksum is rejected and the last good one kept; the audit chain detects a deleted and an edited row; XPC messages and API requests are fuzzed with the parsers; malformed packets and API requests are rejected safely (specs 12.1.1) |
| Compatibility | Oldest and newest supported version of each OS; Linux kernel matrix as in section 5.2 |

## 10. Test data rules

- All fixtures are **generated in the lab** (test servers, test certificates, example domains like `*.example`). Never commit traffic captured from a real user.
- Fixtures and scenarios live in `testdata/` and are reviewed like code.
- Every bug fix adds a fixture or scenario that reproduces the bug.

## 11. CI pipeline

All test workflows are started by hand (`workflow_dispatch`); only **Release** (on a `v*` tag) and
**Version tracking** (on every push to `main`) run automatically. Before each commit the same checks run
locally (`CLAUDE.md`).

| Stage | Where | Contents | Time budget |
|---|---|---|---|
| **Local pre-commit** | Developer machine | `cargo fmt`, `clippy -D warnings`, all tests, the minimum Rust version (1.89), fixture check; clippy for the other two OSes (see the note below) | < 5 min |
| **Tests** (manual) | Linux, macOS, Windows runners | Tag check; smoke, then the whole fast run with `cargo-nextest` (fails over 120 s); doc examples; natively on each OS; Postgres service container loading migrations and seeds; optional ignored conformance tests; `cargo deny` / `cargo audit` (planned) | < 15 min |
| **Sensor tests** (manual) | Privileged runners, Linux kernel matrix | Sensor conformance per OS, integration tests | < 2 h |
| **Fuzz** (manual) | Linux, nightly Rust | Every fuzz target for 30 min | < 2 h |
| **UI tests** (manual) | Linux, Windows | Vitest and Playwright against the mock API (skips until the UI exists) | < 15 min |
| **Release** (tag) | 4 targets | Build, archive, checksums; smoke test runs both binaries and checks the shipped config enables the URL module | < 30 min |
| **Before release** (manual) | Lab machines | End-to-end on installed packages (including file modes, groups and the hardened service unit), release signature and provenance check, performance, 24 h soak, manual macOS checklist (extension approval, notarized install, UI smoke) | 1–2 days |

**Local cross-OS checks.** On macOS, clippy for Linux and Windows leaves out the `sqlite` feature, because
the bundled SQLite is C code that needs a cross compiler; it checks the daemon with `url` and `postgres`
instead. Only the Tests workflow, running natively on each OS, builds SQLite there.

## 12. Coverage and exit criteria

- Line coverage, measured with LLVM source-based coverage (`-C instrument-coverage`, rustup `llvm-tools`):
  ≥ 80% for `core`, `enrich`, `storage-*`, `module-*` and the policy engine; ≥ 60% overall. Unit tests inside
  source files count; `tests/` folders and the config test table don't. After phase 1: 91.7% of product code;
  `enrich` (38%) and `storage-postgres` (3%) are below target until phases 3 and 12.
- Every scenario in section 6 and every sensor conformance case passes on every supported OS.
- No open crash or data-loss bugs; fuzzing has run with no crashes for 7 Fuzz workflow runs in a row.
- Performance and soak targets in section 9 are met.

## 13. Test layout in the repo

```
crates/
  test-support/          FakeSensor, flow() builder, FakeClock, MemoryStore / MemorySink, FaultySink,
                         RecordingAlertSink, module doubles, RecordingEmitter, packet builders,
                         gen-fixtures; planned: MockApiServer, scenario runner
  storage-conformance/   storage contract suite (with module data)
  sensor-conformance/    sensor contract suite + traffic generator
  module-conformance/    module contract suite (+ tests proving it catches faults)
  storage-sqlite/tests/  conformance, schema / migrations, state, sink
  storage-manager/tests/ registry, routing, SQLite end to end
  daemon/tests/          scribed binary, module host
  daemon/src/config/     config tests (bad-config table)
  */tests/, src/         other isolated and unit tests per crate
fuzz/                    cargo-fuzz targets (tls_client_hello, http_request) and generated corpus
testdata/
  pcap/                  14 generated traffic fixtures with expected flows
  events/                raw eBPF / ETW / Network Extension records with expected observations (draft)
  scenarios/             19 daemon YAML scenarios (runner in phase 4)
  db/                    schema snapshots v1 and v2, seeds, build.sh
ui/tests/                Vitest, Playwright, API mocks
tests/e2e/               install / upgrade / uninstall scripts per OS
```
