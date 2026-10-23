# Test approach for scribe

## 1. Goals

- Prove that every outgoing connection is seen, attributed to the right host and process, counted correctly, and stored.
- Prove that each mode (learn, caution, alert) raises exactly the alerts it should, no more and no fewer.
- Let each layer (UI, capture, daemon, storage) be tested **without the others**, so most tests run fast, need no root rights, and run on every pull request.
- Keep privileged tests and tests that depend on a specific OS few, scripted, and run on dedicated CI machines.

## 2. Test levels

| Level | What it covers | Privileges | When it runs |
|---|---|---|---|
| **Unit** | Functions and modules: parsers, scoring rules, config, mode logic | none | every PR |
| **Isolated component** | One layer with all its neighbours replaced by test doubles (sections 4–7) | none* | every PR |
| **Contract / conformance** | Every implementation of a shared interface passes the same suite (storage now; sensors later) | backend-dependent | every PR / nightly |
| **Integration** | Real daemon + real sensor + real storage on one OS | root / admin | nightly |
| **End-to-end** | Installed package, real traffic, CLI / UI checks | root / admin | before release |
| **Non-functional** | Performance, long-running soak, fuzzing, security | mixed | nightly / before release |

\* Except the privileged capture tests in section 5.2.

## 3. How isolation works

The code already has clear boundaries between layers. Each boundary gets a test double:

| Boundary | Real implementation | Test double | Lives in |
|---|---|---|---|
| `Sensor` trait → `FlowEvent` channel | eBPF, ETW, Network Extension, pcap | `FakeSensor` (replays a script of events) | `crates/test-support` |
| `StateStore` / `EventSink` | SQLite, Postgres | `MemoryStore`, `MemorySink`, `FaultySink` (fails or slows down on command) | `crates/test-support`, moved from `storage-conformance/tests/reference.rs` |
| Alert outputs | OS notifications, log, webhook | `RecordingAlertSink` | `crates/test-support` |
| Time | system clock | `FakeClock` (moved forward by the test) | `crates/test-support` |
| Local API (gRPC) | `scribed` | `MockApiServer` built from the same `.proto` | `crates/test-support` + `ui/tests/mocks` |

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

### 5.1 Decoding (no privileges, every PR)

- Turning raw bytes into a `FlowEvent` is kept in plain functions with no OS calls.
- **Inputs:** recorded `.pcap` files and raw eBPF / ETW event records in `testdata/`.
- **Check:** output `FlowEvent`s match expected JSON (golden files).
- **Fixtures needed:**
  - TCP + TLS 1.2 and 1.3 ClientHello with SNI
  - TLS with ECH (no readable SNI)
  - Plaintext HTTP/1.1 with Host header
  - QUIC Initial packet
  - DNS A / AAAA / CNAME chains
  - DNS-over-HTTPS
  - IPv4 and IPv6
  - Fragmented and out-of-order packets
  - Truncated and malformed packets
- **Enrichment tests (`crates/enrich`):** the same fixtures, plus DNS cache expiry tests using `FakeClock`.
- **Fuzzing:** `cargo-fuzz` targets for the DNS, TLS ClientHello, HTTP and QUIC parsers. They must never crash or hang.

### 5.2 OS hookup (privileged, nightly)

The same **sensor conformance suite** (planned `crates/sensor-conformance`) runs against every sensor:

1. Start local test servers: TLS (self-signed cert), plain HTTP, UDP echo, QUIC, DNS.
2. Start the sensor.
3. Make known connections from a known test process.
4. Check that the sensor emits the expected events: destination, port, process ID and path, hostname, TLS/plaintext/QUIC, byte counts. Each event must arrive within 1 second, with nothing missing and nothing duplicated.

| Sensor | Environment | Notes |
|---|---|---|
| Linux eBPF | Network namespace in a VM; kernels 5.8, 5.15, 6.1, latest (via `virtme-ng` or `lvh`) | Also checks that loading falls back to pcap on kernels that are too old |
| Windows ETW | GitHub Windows runner, run as admin | Npcap installed silently for the packet-content tests |
| macOS Network Extension | Self-hosted Mac with an MDM profile that pre-approves the extension | Swift flow-mapping logic is unit-tested with XCTest and mocked `NEFilterFlow` objects; the XPC bridge is tested against a fake extension process, which needs no approval |
| pcap fallback | Linux / macOS / Windows runners | Same suite, but process attribution is expected to be empty |

## 6. Daemon — isolated tests

Run the real pipeline (ingest → enrichment → counters → policy → storage manager) in-process with:
- `FakeSensor` instead of a real sensor
- `MemoryStore` and `MemorySink` instead of real databases
- `RecordingAlertSink` instead of notifications
- `FakeClock` instead of system time

Tests drive it through the real local API.

**Scenario files:** each scenario is a YAML file in `testdata/scenarios/` containing:
- mode and starting baseline
- a script of flow events
- the expected alerts, hosts and counters

The test runner loads the scenario, plays the events through the pipeline, and compares the final state to the expected one.

| Area | Scenarios |
|---|---|
| Learn mode | New hosts are added to the baseline; no alerts; switches automatically to the next mode when learn time ends |
| Caution mode | New ordinary host → no alert; raw IP with no DNS → alert; unusual port → alert; high-entropy domain → alert; plaintext to a **known** host → alert; TLS to a known host → nothing |
| Alert mode | Every host not on the list → alert; listed host over TLS → nothing |
| Alert dedupe | Same host + process within the window → one alert; after the window → new alert; acknowledged → silent |
| Counters | N connections, M requests, B bytes per host and per process are exact; concurrent flows to the same host |
| Hostname | Host from SNI beats DNS cache; expired DNS entry → shown as an IP; ECH / DoH → host shown as "unresolved" |
| API | Change mode, add/remove baseline entries, list hosts, page through results, read health |
| Robustness | Slow sink doesn't slow capture; storage outage → events spooled, then replayed; full queue → drops are counted, not crashes |
| Lifecycle | Restart keeps hosts, counters, baseline and mode; config reload; clean shutdown flushes all sinks |

**Service integration** (systemd, launchd, Windows Service Control Manager: start, stop, restart, privilege drop) is checked in the packaging stage, not here.

## 7. Storage — isolated tests

| Test | How | When |
|---|---|---|
| **Conformance suite** (`crates/storage-conformance`) | The same suite runs against `MemoryStore`, SQLite and Postgres | every PR |
| SQLite | Fresh temporary file per test, plus an in-memory database | every PR |
| Postgres | Postgres service container in CI (`SCRIBE_TEST_POSTGRES_URL`), a fresh database per run | every PR |
| Migrations | Start from a saved database for each past schema version, migrate, check the data; migration runs twice without changes | every PR |
| Property tests (`proptest`) | Random sequences of host updates: stored counters equal the sum of the updates; flags only turn on, never off | every PR |
| Concurrency | Many tasks update the same host at once; no lost updates | every PR |
| Failure injection | `FaultySink` / a broken connection / disk full: errors reported, no corruption, manager spools | every PR |
| Storage manager | With `MemoryStore` + `FaultySink`: batching by size and time, a failing sink doesn't affect others, spool replays in order, retention removes old events | every PR |
| Volume | 10M events, 100k hosts: write rate, query time, database size | nightly |

**Adding a new storage backend:** it must pass the whole conformance suite before it can be registered in `Registry::with_builtin`.

## 8. Integration and end-to-end tests

- **Integration (nightly, per OS):** the real daemon with the real sensor and SQLite, in a VM. A traffic generator makes scripted connections, and the test checks the result through the CLI (`scribe hosts`, `scribe status`).
- **End-to-end (before release):**
  1. Install the package (`.deb`, `.rpm`, MSI or `.pkg`).
  2. Run learn mode for 10 minutes on test traffic.
  3. Switch to caution, then alert, checking alerts at each step.
  4. Upgrade the package and check the data survives.
  5. Uninstall and check nothing is left behind.

## 9. Non-functional tests

| Type | Target |
|---|---|
| Performance | 1,000 new connections/s: < 2% CPU on one core and < 100 MB memory for the daemon; event-to-database latency p99 < 1 s |
| Soak | 24 h of mixed traffic: memory stays flat, no file handle leaks, spool stays empty |
| Fuzzing | All parsers fuzzed for 30 min nightly; any crash found becomes a fixture |
| Security | Daemon drops privileges after the sensor starts; API socket is accessible only to the owner and the admin group; malformed packets and API requests are rejected safely |
| Compatibility | Oldest and newest supported version of each OS; Linux kernel matrix as in section 5.2 |

## 10. Test data rules

- All fixtures are **generated in the lab** (test servers, test certificates, example domains like `*.example`). Never commit traffic captured from a real user.
- Fixtures and scenarios live in `testdata/` and are reviewed like code.
- Every bug fix adds a fixture or scenario that reproduces the bug.

## 11. CI pipeline

| Stage | Contents | Time budget |
|---|---|---|
| **Every PR** | `cargo fmt`, `clippy`, unit tests, isolated component tests (UI, decoding, daemon, storage manager), storage conformance on SQLite and Postgres, migration and property tests | < 15 min |
| **Nightly** | Privileged sensor conformance on each OS and the Linux kernel matrix, integration tests, fuzzing, storage volume test | < 2 h |
| **Before release** | End-to-end on installed packages, performance, 24 h soak, manual macOS checklist (extension approval, notarized install, UI smoke) | 1–2 days |

## 12. Coverage and exit criteria

- Line coverage (`cargo llvm-cov`): ≥ 80% for `core`, `enrich`, `storage-*` and the policy engine; ≥ 60% overall.
- Every scenario in section 6 and every sensor conformance case passes on every supported OS.
- No open crash or data-loss bugs; fuzzing has run with no crashes for 7 nightly runs in a row.
- Performance and soak targets in section 9 are met.

## 13. Planned test layout in the repo

```
crates/
  test-support/          FakeSensor, FakeClock, MemoryStore/MemorySink, FaultySink,
                         RecordingAlertSink, MockApiServer, scenario runner
  storage-conformance/   (exists) storage contract suite
  sensor-conformance/    sensor contract suite + traffic generator
  */tests/               isolated component tests per crate
fuzz/                    cargo-fuzz targets for parsers
testdata/
  pcap/                  recorded traffic fixtures
  events/                raw eBPF / ETW records
  scenarios/             daemon YAML scenarios
  db/                    saved databases for migration tests
ui/tests/                Vitest, Playwright, API mocks
tests/e2e/               install / upgrade / uninstall scripts per OS
```
