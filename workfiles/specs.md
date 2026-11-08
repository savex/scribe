# scribe specification

*Version 0.1 (draft), 2026-11-08, describing the project at commit `fd170fb`.*
Built from [plan.md](plan.md), [diagram.md](diagram.md), [status.md](status.md) and the
[scribe-conventions skill](../.claude/skills/scribe-conventions/SKILL.md). When they disagree,
the code and the skill win; update this document in the same commit.

**Status legend** used throughout:

| Status | Meaning |
|---|---|
| **Implemented** | Works today and has tests or a verified check |
| **Stub** | Code and interface exist, behaviour doesn't (returns "not implemented" or does nothing) |
| **Planned** | Agreed and scheduled in the plan; no code yet |
| **Proposed** | Suggested value or design, not yet confirmed |
| **Open** | Needs a decision |

---

## 1. Purpose and scope

scribe logs and tracks every outgoing connection from a host. For each connection it records
where it went (host name, IP, port, URL for plaintext HTTP), which process made it, how often,
and whether it used TLS. It learns what normal looks like and reports what doesn't.

**In scope**
- macOS, Linux and Windows hosts.
- Outgoing TCP connections and UDP / QUIC flows, IPv4 and IPv6.
- A background daemon, a command line client, and later an optional desktop UI.
- Local storage (SQLite) with an optional central store (PostgreSQL).

**Out of scope** (decided)
- Blocking or modifying traffic. Possible later feature (nftables, Network Extension verdicts, WFP).
- Reading full URLs or content inside TLS. Would need a MITM proxy; if ever added, a separate opt-in module.
- Incoming connections.
- Storage backends other than SQLite and PostgreSQL (ClickHouse, OpenSearch, file sinks, external storage plugins were dropped).

## 2. Glossary

| Term | Meaning |
|---|---|
| Flow | One outgoing TCP connection, or one UDP / QUIC exchange between two endpoints |
| Host | A destination, identified by host name, or by IP when no name is known ("unresolved") |
| Baseline | The list of known hosts for a profile; entries are *learned* or *manual* |
| Profile | A named baseline, e.g. `default`, `work`, `home` |
| Mode | How the policy engine reacts to traffic: `learn`, `caution` or `alert` |
| Sensor | The OS-specific capture component that reports flows |
| State store | The one storage backend holding hosts, counters, baselines and alert state |
| Event sink | A storage backend receiving append-only flow, alert and audit records |
| SNI | Server Name Indication: the host name a TLS client sends in clear in its first message |
| ECH | Encrypted Client Hello: hides the real SNI behind a provider's public name |
| QUIC | UDP-based transport under HTTP/3; its first packets can be decrypted to read the SNI |

## 3. Actors

| Actor | Goal |
|---|---|
| **Host owner** | Know what their own machine talks to, and be told about anything unusual |
| **Administrator / security engineer** | Monitor one or more hosts strictly, investigate alerts, maintain baselines |
| **Fleet operator** | Collect history from many hosts in a central PostgreSQL database |
| **Developer** | Add storage backends or sensors, and keep them correct through the conformance suites |
| **Service manager** | systemd, launchd or the Windows Service Control Manager: starts and stops `scribed` |

## 4. Use cases

| ID | Use case | Actor | Mode | Status |
|---|---|---|---|---|
| UC-1 | Build a baseline of normal traffic | Host owner, admin | learn | Planned |
| UC-2 | Watch for unusual destinations | Host owner | caution | Planned |
| UC-3 | Strict allowlist monitoring | Admin | alert | Planned |
| UC-4 | Find unencrypted traffic | Host owner, admin | caution, alert | Planned |
| UC-5 | Review tracked hosts and counters | All users | any | Planned |
| UC-6 | Find which process talks to a host | Admin | any | Planned |
| UC-7 | Handle an alert | Host owner, admin | caution, alert | Planned |
| UC-8 | Switch mode and manage baselines | Admin | any | Planned |
| UC-9 | Send history to a central database | Fleet operator | any | Planned |
| UC-10 | Install, upgrade and uninstall | Admin | — | Planned (release archives exist) |
| UC-11 | Extend scribe with a backend or sensor | Developer | — | Implemented (interfaces and conformance suites) |

### UC-1 Build a baseline (learn mode)
1. The admin installs scribe; it starts in `learn` mode (the default).
2. scribed records every flow and adds each new host to the baseline of the active profile, marked *learned*.
3. No alerts are raised, not even for plaintext or raw-IP traffic.
4. Optionally, learn mode ends after a set time (`learn_for`, e.g. `7d`) and switches to the next mode (`then`, e.g. `caution`).

**Result:** a baseline that describes normal traffic. Scenarios: `learn-adds-hosts-no-alerts`, `learn-auto-switch`.

### UC-2 Watch for unusual destinations (caution mode)
1. A flow arrives for a host that isn't on the baseline.
2. The policy engine scores it with the non-ordinary rules (section 8.3).
3. If the score passes the threshold, an alert is raised with the highest-scoring reason; ordinary new hosts (DNS name, TLS, port 443, known process) pass silently.

Scenarios: `caution-ordinary-new-host`, `caution-raw-ip`, `caution-high-entropy-domain`.

### UC-3 Strict allowlist monitoring (alert mode)
Every flow to a host not on the baseline raises an alert (`unlisted_host`). Listed hosts over TLS stay quiet. Scenario: `alert-unlisted-host`.

### UC-4 Find unencrypted traffic
In `caution` and `alert` modes, any plaintext flow raises an alert (`plaintext`), even to a listed host. For plaintext HTTP the alert includes the full URL. Scenario: `caution-plaintext-known-host`.

### UC-5 Review tracked hosts
The user runs `scribe hosts` (or opens the UI) and sees every host with first / last seen, connection, request and byte counters, TLS / plaintext flags, the processes involved and whether the host is on the baseline. Unresolved hosts appear by IP. Scenario: `counters-exact`, `hostname-unresolved`.

### UC-6 Find which process talks to a host
Hosts and alerts carry the process path and pid when the sensor can see them (native sensors). With the pcap fallback, process fields are empty and the UI says so.

### UC-7 Handle an alert
1. The user gets an OS notification (and a log entry, optionally a webhook call).
2. They review it with `scribe alerts` or in the UI.
3. They either acknowledge it (`scribe alerts ack`), which silences repeats, or add the host to the baseline (`scribe baseline add`).
4. Repeats from the same host and process within the dedupe window don't raise new alerts. Scenario: `alert-dedupe-window`.

### UC-8 Switch mode and manage baselines
The admin changes the mode at runtime (`scribe mode caution`); it applies from the next flow, and hosts learned before stay quiet. Baselines are kept per profile and edited with `scribe baseline add/rm`. Scenario: `mode-switch-via-api`.

### UC-9 Send history to a central database
The fleet operator adds a PostgreSQL event sink to each host's config, subscribed to `flow` and `alert` events. Local SQLite stays the state store. If the central database is unreachable, events are spooled locally and replayed in order when it returns.

### UC-10 Install, upgrade, uninstall
The admin installs a package (`.deb` / `.rpm`, notarized `.pkg`, MSI); the service starts and reports healthy. Upgrades keep hosts, counters, baselines and mode. Uninstall removes the service and binaries, and the data only on request. Covered by `tests/e2e/`.

### UC-11 Extend scribe
A developer adds a storage backend by implementing `StorageFactory` plus `StateStore` and / or `EventSink`, or a sensor by implementing `Sensor`. It's accepted only after passing `scribe-storage-conformance` or `scribe-sensor-conformance`.

## 5. Requirements

### 5.1 Functional

| ID | Requirement | Status | Verified by |
|---|---|---|---|
| FR-1 | Capture every outgoing TCP connection and UDP / QUIC flow, IPv4 and IPv6, on macOS, Linux and Windows | Stub | Sensor conformance suite; pcap fixtures |
| FR-2 | Attribute each flow to its process (pid and path) where the sensor allows; the pcap fallback reports no process | Stub | Sensor conformance (`expect_process_info`) |
| FR-3 | Find the host name in this order: TLS SNI, HTTP `Host` header, DNS cache (IP → queried name, CNAME chains map back to the queried name) | Partly (DNS cache) | pcap fixtures `tls13_sni_ipv4`, `http_plain`, `dns_cname_then_tls`, `dns_aaaa_then_tls` |
| FR-4 | Classify each flow as `tls`, `quic`, `plaintext` or `unknown` from its first bytes, never from the port | Partly (TCP) | Unit tests in `enrich`; fixtures |
| FR-5 | For ECH, record the outer public name and flag the flow `ech` | Planned | Fixture `tls_ech` |
| FR-6 | For QUIC, read the SNI from the Initial packet (using `ring` 0.17) | Planned | Fixture to be checked against RFC 9001 Appendix A |
| FR-7 | Track hosts without a name by IP, flagged unresolved; never drop them | Planned | Scenario `hostname-unresolved`; fixture `doh` |
| FR-8 | Record the full URL for plaintext HTTP requests | Planned | Fixture `http_plain` |
| FR-9 | Keep connection, request and byte counters per host and per process + host, plus hourly buckets; updates are deltas | Planned | Scenario `counters-exact`; storage conformance |
| FR-10 | Keep each host's first seen, last seen, `tls_seen` and `plaintext_seen` (flags only turn on) | Stub | Storage conformance |
| FR-11 | Support the modes `learn`, `caution` and `alert` with the behaviour in section 8 | Planned | Scenarios |
| FR-12 | Support time-limited learn mode that switches to a chosen mode | Planned | Scenario `learn-auto-switch` |
| FR-13 | Keep baselines per profile with learned / manual entries; add and remove entries | Stub | Storage conformance; scenarios |
| FR-14 | Score unlisted hosts with the non-ordinary rules and report the reason | Planned | Caution scenarios |
| FR-15 | Deduplicate alerts per host + process within a window; support acknowledging | Planned | Scenario `alert-dedupe-window` |
| FR-16 | Deliver alerts as OS notifications, log entries and optional webhook calls | Planned | `RecordingAlertSink` in daemon tests |
| FR-17 | Store state in exactly one state store and events in zero or more event sinks, each subscribed to event kinds | Partly (routing written, untested) / Stub (backends) | Storage conformance; manager tests (planned) |
| FR-18 | Provide SQLite (default) and PostgreSQL (feature `postgres`) backends | Stub | Storage conformance; Tests workflow |
| FR-19 | Spool events when a sink fails and replay them in order; enforce per-sink retention | Planned | `FaultySink` tests (planned) |
| FR-20 | Expose a local API for the CLI and UI, including runtime mode changes | Planned | API tests with `MockApiServer` (planned) |
| FR-21 | Provide the CLI commands in section 6.2 | Partly (`version`, mode checking) | CLI tests (planned) |
| FR-22 | Load and validate a TOML config file; report errors with line numbers | Planned (phase 0) | Config tests (planned) |
| FR-23 | Report the version from the nearest git tag (`scribe --version`, `scribed --version`) | Implemented | Release workflow smoke check |
| FR-24 | Export hosts and baselines | Planned | — |

### 5.2 Non-functional

| ID | Requirement | Target | Status |
|---|---|---|---|
| NFR-1 | Throughput | 1,000 new connections/s | Proposed |
| NFR-2 | CPU overhead | < 2% of one core at NFR-1 | Proposed |
| NFR-3 | Memory | Daemon < 100 MB | Proposed |
| NFR-4 | Latency | Flow to database p99 < 1 s; sensor reports each flow within 1 s | Proposed (1 s sensor deadline is decided) |
| NFR-5 | Stability | 24 h soak with flat memory, no handle leaks, empty spool | Proposed |
| NFR-6 | Durability | Restart keeps hosts, counters, baselines and mode; sink outages lose no events within the spool cap | Planned |
| NFR-7 | Isolation | A slow or failing sink never blocks capture or other sinks | Planned |
| NFR-8 | Privileges | Runs as root / SYSTEM only as long as the sensor needs; drops privileges after start | Proposed |
| NFR-9 | API access | Local socket / named pipe readable only by the owner and the admin group | Proposed |
| NFR-10 | Secrets | Database credentials from the OS keychain, DPAPI, Secret Service or a root-only file; never in plain config | Proposed |
| NFR-11 | Robust parsing | Packet parsers never crash or hang on malformed input; fuzzed, crash-free for 7 runs in a row before release | Planned |
| NFR-12 | Privacy | Store connection metadata only, never payloads; data leaves the host only through sinks the admin configures | Proposed |
| NFR-13 | Portability | Prebuilt binaries for `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc` | Implemented (archives) |
| NFR-14 | Build | Minimum Rust 1.70 today; raising it is an open decision (plan risk 6) | Open |
| NFR-15 | Quality | Coverage ≥ 80% for `core`, `enrich`, `storage-*` and the policy engine; ≥ 60% overall | Proposed (today 5% of product code) |
| NFR-16 | Extensibility | New backends and sensors must pass their conformance suites | Implemented |

## 6. Entry points

### 6.1 `scribed` (daemon)

Started by the service manager as root / SYSTEM: systemd unit `scribed` (Linux), launchd `com.scribe.daemon` (macOS), Windows service `scribed` (all proposed names).

| Invocation | Effect | Status |
|---|---|---|
| `scribed` | Run the service. Today: prints version, mode, sensor and storage backends, then exits | Stub |
| `scribed --version`, `-V` | Print `scribed <version>` | Implemented |
| `scribed --config <path>` | Use this config file | Proposed (phase 0) |
| `scribed --check-config` | Print the effective config and exit | Proposed (phase 0) |
| SIGTERM / Ctrl-C / service stop | Flush sinks and shut down cleanly | Planned (phase 0) |

### 6.2 `scribe` (CLI)

Talks to `scribed` through the local API.

| Command | Effect | Status |
|---|---|---|
| `scribe version`, `--version`, `-V` | Print `scribe <version>` | Implemented |
| `scribe status` | Daemon, sensor and storage health; current mode and profile | Stub |
| `scribe hosts` | Tracked hosts with counters and flags | Stub |
| `scribe mode <learn\|caution\|alert>` | Switch mode | Stub (mode name checking works) |
| `scribe alerts` | List alerts | Planned |
| `scribe alerts ack <id>` | Acknowledge an alert | Planned |
| `scribe baseline add\|rm <host>` | Edit the active profile's baseline | Planned |
| `scribe export` | Dump hosts and baseline | Stub |

Exit codes: `0` success, `1` failure, `2` usage error (current behaviour).

### 6.3 Local API

gRPC (`tonic`) over a Unix socket (Linux, macOS) or named pipe (Windows); **Planned**. Its calls follow the CLI and the UI mock data in `ui/tests/mocks/api-scenarios/`:
status, list hosts (paged, filtered), list / stream alerts, acknowledge alert, set mode, get / edit baseline, export. The API reports `api_version` so the UI can detect a mismatch.

### 6.4 Desktop UI

Tauri app talking only to the local API; **Planned** (not in the 14 phases). Test folders and mock API data exist.

### 6.5 macOS Network Extension

`ScribeExtension`, a Swift System Extension (`NEFilterDataProvider`) started by macOS after user or MDM approval. Sends flow messages to `scribed` over XPC (draft format in `testdata/events/macos-ne/`). **Planned.**

### 6.6 Development and release entry points (implemented)

| Entry point | Purpose |
|---|---|
| `cargo run -p scribe-test-support --bin gen-fixtures [-- --check]` | Regenerate or check pcap fixtures and fuzz seeds |
| `scripts/version.sh` | Show, compute, set and check versions |
| `testdata/db/build.sh` | Rebuild schema snapshots |
| GitHub workflows | Release and Version tracking (automatic); Bump version, Tests, Sensor tests, Fuzz, UI tests, End-to-end (manual) |
| VSCodium tasks and launch configs | Build, test, debug, local CI run |

## 7. Modules

The flow of data, from [diagram.md](diagram.md): OS network stack → sensor → ingest → enrichment →
counters → policy engine → storage manager → state store and event sinks; alerts go to the alert
outputs; the CLI and UI read and control everything through the local API.

### 7.1 Product modules

| Module | Location | Responsibility | Depends on | Status |
|---|---|---|---|---|
| Core | `crates/core` | `FlowEvent`, `Mode`, `Sensor`, `Clock`, `Alert` / `AlertOutput`, `VERSION` | — | Partly (types written, untested); config and logging planned |
| Enrichment | `crates/enrich` | DNS cache, SNI / HTTP / DNS / QUIC parsing, security classification | core | Partly (TLS detection, DNS cache) |
| Linux sensor | `crates/sensor-linux` | eBPF probes with `aya`, process lookup | core | Stub |
| Windows sensor | `crates/sensor-windows` | ETW kernel-network and DNS-client events, Npcap for payloads | core | Stub |
| pcap sensor | `crates/sensor-pcap` | Fallback capture on every OS, no process info | core | Stub |
| macOS extension | `macos/ScribeExtension` | Network Extension + XPC bridge | — | Planned |
| Storage API | `crates/storage-api` | `StateStore`, `EventSink`, `StorageFactory`, data model, errors | core | Implemented (interfaces) |
| Storage manager | `crates/storage-manager` | Backend registry, routing to sinks; later host cache, batching, spool, retention | storage-api, backends | Partly (registry, routing) |
| SQLite backend | `crates/storage-sqlite` | Default state store and event sink | storage-api | Stub (schema v1 done) |
| PostgreSQL backend | `crates/storage-postgres` | Optional state store and event sink | storage-api | Stub (schema v1 done) |
| Policy engine | new crate, name open (e.g. `crates/policy`) | Modes, scoring rules, dedupe, learn time limit | core, storage-api | Planned |
| Alert outputs | new module, location open | OS notifications, log, webhook | core | Planned (interface exists) |
| Local API | new crate + `proto/`, name open | gRPC service and client | core, storage-api | Planned |
| Daemon | `crates/daemon` (`scribed`) | Wires everything; config, logging, service lifecycle | all of the above | Stub |
| CLI | `crates/cli` (`scribe`) | Command line client | core, API client | Partly |

### 7.2 Test and support modules (implemented)

| Module | Location | Responsibility |
|---|---|---|
| Test support | `crates/test-support` | `FakeSensor`, `FakeClock`, `MemoryStore`, `MemorySink`, `FaultySink`, `RecordingAlertSink`, packet builders, pcap writer, `gen-fixtures` |
| Storage conformance | `crates/storage-conformance` | Contract tests for every storage backend |
| Sensor conformance | `crates/sensor-conformance` | Contract tests for every sensor, plus the local traffic generator |
| Test data | `testdata/` | pcap fixtures, scenarios, raw sensor records, schema snapshots |
| Fuzzing | `fuzz/` | cargo-fuzz targets and seeds |
| End-to-end | `tests/e2e/` | Install, mode, upgrade, uninstall scripts per OS |

## 8. Behaviour

### 8.1 Modes

| Flow | `learn` | `caution` | `alert` |
|---|---|---|---|
| Listed host, TLS / QUIC | record | record | record |
| Listed host, plaintext | record | **alert** `plaintext` | **alert** `plaintext` |
| Unlisted host, looks ordinary | record, add to baseline | record | **alert** `unlisted_host` |
| Unlisted host, non-ordinary | record, add to baseline | **alert** (top reason) | **alert** |

Every flow updates the counters, whatever the mode.

### 8.2 Mode changes

```
learn ──(learn_for elapsed)──▶ then (caution | alert)
any   ──(scribe mode X / API)──▶ X        applies from the next flow
```
The default mode is `learn`. Hosts added to the baseline in learn mode stay listed after a switch.

### 8.3 Non-ordinary signals (caution mode)

| Reason | Signal | Status |
|---|---|---|
| `raw_ip` | Connection to an IP with no DNS lookup before it | Proposed |
| `unusual_port` | Port outside the usual set | Proposed (port list open) |
| `high_entropy` | Random-looking (DGA-style) domain labels | Proposed |
| `new_tld` | Top-level domain not seen before | Proposed |
| `new_process` | Process that never made network connections before | Proposed |
| `threat_list` | Host on a threat list | Proposed (list sources open) |

Each rule returns a score and a reason; scores and the alert threshold are **open**.

### 8.4 Degraded operation

| Situation | Behaviour | Status |
|---|---|---|
| Native sensor unavailable (old kernel, extension not approved) | Fall back to the pcap sensor; status reports no process info | Planned |
| Event sink down | Spool locally, replay in order; at the spool cap drop the oldest and count drops | Proposed |
| State store unavailable | Keep counting in memory, report unhealthy | Open |
| Hostname hidden (ECH, DoH) | Track by IP or outer name, flag it | Planned |
| Invalid config | Refuse to start, report the error and line | Planned |

## 9. Options

### 9.1 Config file (`scribed`)

TOML. Example: [config/scribe.example.toml](../config/scribe.example.toml). Loading is planned for phase 0.

| Key | Type | Default | Status |
|---|---|---|---|
| `mode` | `learn` \| `caution` \| `alert` | `learn` | Decided |
| `profile` | string | `default` | Decided |
| `[storage.state] kind` | `sqlite` \| `postgres` | `sqlite` | Decided |
| `[storage.state] path` (SQLite) | path | `<data dir>/state.db` | Proposed |
| `[storage.state] url` (Postgres) | URL without password | — | Decided |
| `[storage.state] credentials` (Postgres) | secret reference, e.g. `keychain:scribe-postgres` | — | Proposed |
| `[[storage.sinks]] name` | string | `local-history` | Proposed |
| `[[storage.sinks]] kind` | `sqlite` \| `postgres` | `sqlite` | Decided |
| `[[storage.sinks]] path` / `url` / `credentials` | as above | `<data dir>/events.db` | Proposed |
| `[[storage.sinks]] events` | list of `flow`, `alert`, `audit` | all | Decided |
| `[[storage.sinks]] retention` | duration (`30d`, `10m`, `1h`, `45s`) | `30d` | Proposed |
| `[policy] learn_for` | duration | none (learn until changed) | Proposed |
| `[policy] then` | `caution` \| `alert` | `caution` | Proposed |
| `[policy] dedupe_window` | duration | `10m` | Proposed |
| `[policy] usual_ports`, `threshold`, `threat_lists` | — | — | Open |
| `[log] level` | `error` … `trace` | `info` | Proposed (phase 0) |
| `[log] format` | `text` \| `json` | `text` | Proposed (phase 0) |
| `[log] file` | path, rotated daily | none (stderr) | Proposed (phase 0) |

**Default locations** (proposed, to confirm in phase 0):

| OS | Config file | Data directory |
|---|---|---|
| Linux | `/etc/scribe/scribe.toml` | `/var/lib/scribe/` |
| macOS | `/Library/Application Support/scribe/scribe.toml` | same folder |
| Windows | `%ProgramData%\scribe\scribe.toml` | same folder |

Precedence: `--config` flag, then `SCRIBE_CONFIG`, then the OS default; with no file, built-in defaults (proposed).

### 9.2 Environment variables

| Variable | Used by | Purpose | Status |
|---|---|---|---|
| `SCRIBE_CONFIG` | `scribed` | Config file path | Proposed |
| `SCRIBE_LOG` | `scribed` | Log filter, `RUST_LOG` syntax; overrides `[log] level` | Proposed |
| `SCRIBE_VERSION` | build | Overrides the version baked into the binaries (release builds) | Implemented |
| `SCRIBE_TEST_POSTGRES_URL` | tests | Disposable Postgres database for conformance tests | Implemented |

### 9.3 Build options

| Option | Effect | Status |
|---|---|---|
| Cargo feature `sqlite` (default) | Build the SQLite backend | Implemented |
| Cargo feature `postgres` | Build the PostgreSQL backend | Implemented |
| `--all-features` | Both backends | Implemented |

## 10. Data

### 10.1 Flow event (`scribe_core::FlowEvent`)

| Field | Meaning |
|---|---|
| `ts` | Time observed |
| `pid`, `process_path` | Process, when the sensor can tell |
| `proto` | `tcp`, `udp` or `quic` |
| `src`, `dst_ip`, `dst_port` | Endpoints |
| `hostname` | From SNI, HTTP Host or DNS correlation |
| `url` | Plaintext HTTP only |
| `security` | `tls`, `quic`, `plaintext` or `unknown` |
| `bytes_out` | Bytes sent |
| `kind` | `new_flow`, `request` or `close` |

### 10.2 Stored data (schema v1)

| Table | Content |
|---|---|
| `hosts` | name, first / last seen, connection / request / byte counters, TLS and plaintext flags |
| `host_ips` | IP addresses per host with expiry (from DNS TTLs) |
| `baseline_entries` | profile, host, source (`learned` / `manual`), added at |
| `alert_state` | dedupe key (host + process), last alerted, acknowledged |
| `events` | flow / alert / audit records with timestamp, host, schema version and JSON payload |
| `schema_migrations` | applied migration versions |

SQLite stores timestamps as epoch milliseconds; PostgreSQL uses `TIMESTAMPTZ`, `INET` and `JSONB`.

## 11. Platform support

| | Linux | macOS | Windows |
|---|---|---|---|
| Native capture | eBPF (`aya`), kernel 5.8+ | Network Extension (Swift) | ETW |
| Process attribution | yes | yes | yes |
| Packet contents (SNI) | eBPF socket filter | Network Extension first bytes | Npcap |
| Fallback | libpcap | libpcap | Npcap |
| Service | systemd | launchd | Windows service |
| Installer | `.deb`, `.rpm` | notarized `.pkg` | MSI |
| Today | stub | not started | stub |

## 12. Security and privacy

- Capture needs root / SYSTEM, an approved Network Extension (macOS), or Npcap (Windows). The daemon should drop privileges once the sensor runs (NFR-8).
- Every parser reads untrusted bytes and is fuzzed (NFR-11).
- Only metadata is stored. Plaintext URLs can contain sensitive query strings; whether to strip query strings is **open**.
- Data stays on the host unless the admin configures a remote sink; credentials never sit in plain config (NFR-10).
- Test data never contains real user traffic; only documentation address ranges and `example.com` / `example.net` names.

## 13. Versioning and release

Versions come from `vMAJOR.MINOR.PATCH[-PRERELEASE]` git tags; `Cargo.toml` always matches the latest
tag. Pushing a tag (or running **Bump version**) builds and publishes a GitHub Release with archives
for the four targets and `SHA256SUMS`. Details: skill section 10, readme "Versioning".

## 14. Verification

How each requirement group is tested (see [test-approach.md](test-approach.md)):

| Area | Test assets | Ready |
|---|---|---|
| Parsing and enrichment (FR-3 – FR-8) | 13 pcap fixtures with expected flows, fuzz targets | Yes, except QUIC |
| Policy and modes (FR-11 – FR-15) | 11 daemon scenarios with `FakeSensor`, `MemoryStore`, `FakeClock` | Yes (runner planned) |
| Storage (FR-9, FR-10, FR-17 – FR-19) | Storage conformance suite, schema snapshots, `FaultySink` | Yes |
| Capture (FR-1, FR-2) | Sensor conformance suite and traffic generator, draft raw records | Yes |
| API and UI (FR-20) | Mock API scenarios | Partly |
| Install and upgrade (UC-10) | End-to-end scripts | Yes (need installers) |
| Non-functional (NFR-1 – NFR-5) | Performance and soak runs | Planned |

## 15. Open questions

1. Minimum Rust version: keep 1.70 with the fallback resolver, or raise to 1.85 (plan risk 6).
2. Default config and data paths per OS (section 9.1).
3. Scores, threshold, usual ports and threat-list sources for caution mode.
4. Behaviour when the state store is unavailable.
5. Host cache and spool size limits.
6. Whether to strip query strings from stored URLs.
7. Names and locations of the policy engine, alert outputs and local API crates.
8. Log location on Windows and macOS (Event Log, unified logging).

## 16. References

- [plan.md](plan.md) — phases, estimates, milestones, risks
- [diagram.md](diagram.md) — components, connection flow, mode decision, storage plugin classes
- [status.md](status.md) — completion and coverage per module
- [test-approach.md](test-approach.md) — test levels and tooling
- [scribe-conventions skill](../.claude/skills/scribe-conventions/SKILL.md) — decided values
- [readme.md](../readme.md) — overview, build, versioning, workflows
