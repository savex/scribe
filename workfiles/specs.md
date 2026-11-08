# scribe specification

*Version 0.4 (draft), 2026-11-08: adds the `scribe daemon` subcommands (status, health, reset, hibernate, wakeup) and the daemon run states. 0.3: all open questions answered; phase 0 (config, logging, daemon lifecycle, CLI parsing) implemented.*
Built from [plan.md](plan.md), [diagram.md](diagram.md), [status.md](status.md) and the
[scribe-conventions skill](../.claude/skills/scribe-conventions/SKILL.md). When they disagree,
the code and the skill win; update this document in the same commit.

**Status legend** used throughout:

| Status | Meaning |
|---|---|
| **Implemented** | Works today and has tests or a verified check |
| **Stub** | Code and interface exist, behaviour doesn't (returns "not implemented" or does nothing) |
| **Planned** | Agreed and scheduled in the plan; no code yet |
| **Draft default** | Default value in the v1 config draft ([config/scribe.toml](../config/scribe.toml)); accepted as the starting point, tunable after testing |
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
| UC-12 | Check and control the running daemon | Admin, service manager, monitoring | any | Planned |

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

### UC-12 Check and control the running daemon
1. Monitoring or a service manager runs `scribe daemon health` every minute and acts on exit code `1`.
2. The admin runs `scribe daemon status` to see why: drops, an unhealthy sink, a full spool, a fallback sensor.
3. After editing `scribe.toml` the admin applies it with `scribe daemon reset --config` (or SIGHUP), without losing the pipeline state; `scribe daemon reset --counters` starts a clean measurement window.
4. For a planned maintenance window or a noisy test, the admin runs `scribe daemon hibernate --for 1h`; scribe records nothing and alerts on nothing until `scribe daemon wakeup` or the hour is over. The gap is visible in `status`, the log and the stored history.

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
| FR-21 | Provide the CLI commands in section 6.2 | Partly (all commands parsed; only `version` works until the API exists) | `scribe-cli` unit and binary tests |
| FR-22 | Load and validate a TOML config file; report errors with line numbers | Implemented | `scribe-daemon` config tests; shipped file equals built-in defaults |
| FR-23 | Report the version from the nearest git tag (`scribe --version`, `scribed --version`) | Implemented | Release workflow smoke check |
| FR-24 | Export hosts and baselines | Planned | — |
| FR-25 | While the state store is unavailable, keep the latest events in a bounded in-memory buffer; when full, drop the oldest to add the newest; count drops; replay in order on recovery | Planned | `FaultySink`-style state-store tests (planned) |
| FR-26 | Store plaintext URLs according to `privacy.url_query`; always remove user info (`user:password@`) | Planned | Unit tests (planned); fixture `http_plain` |
| FR-27 | `scribe daemon status` shows the run state, live counters and critical metrics (section 6.2.1); `scribe status` is its short form | Planned | API tests; CLI output tests with `MockApiServer` |
| FR-28 | `scribe daemon health` reports healthy / degraded / unhealthy with reasons, exits `0` / `1`, and answers within its timeout; also over `grpc.health.v1` | Planned | Daemon tests with `FaultySink` and a stopped `FakeSensor`; mock `daemon-down` |
| FR-29 | `scribe daemon reset` clears runtime counters and caches and reloads the config without a restart; never changes stored history; an invalid config is rejected and the running one kept | Planned | Daemon tests; config error table reused for reload |
| FR-30 | `scribe daemon hibernate [--for]` stops capture and processing while the daemon keeps serving the API; the pause is recorded and visible | Planned | Daemon tests with `FakeSensor` and `FakeClock`; sensor conformance (stop and start again) |
| FR-31 | `scribe daemon wakeup` (or the end of `--for`) resumes processing with the same mode, baseline and caches | Planned | Same as FR-30 |

### 5.2 Non-functional

| ID | Requirement | Target | Status |
|---|---|---|---|
| NFR-1 | Throughput | 1,000 new connections/s | Proposed |
| NFR-2 | CPU overhead | < 2% of one core at NFR-1 | Proposed |
| NFR-3 | Memory | Daemon < 100 MB; the default cache (32 MiB) and buffer (32 MiB) budgets fit inside it | Proposed |
| NFR-4 | Latency | Flow to database p99 < 1 s; sensor reports each flow within 1 s | Proposed (1 s sensor deadline is decided) |
| NFR-5 | Stability | 24 h soak with flat memory, no handle leaks, empty spool | Proposed |
| NFR-6 | Durability | Restart keeps hosts, counters, baselines and mode; sink outages lose no events within the spool cap | Planned |
| NFR-7 | Isolation | A slow or failing sink never blocks capture or other sinks | Planned |
| NFR-8 | Privileges | Runs as root / SYSTEM only as long as the sensor needs; drops privileges after start | Proposed |
| NFR-9 | API access | Local socket / named pipe readable only by the owner and the admin group | Proposed |
| NFR-10 | Secrets | Database credentials from the OS keychain, DPAPI, Secret Service or a root-only file; never in plain config | Proposed |
| NFR-11 | Robust parsing | Packet parsers never crash or hang on malformed input; fuzzed, crash-free for 7 runs in a row before release | Planned |
| NFR-12 | Privacy | Store connection metadata only, never payloads; redact URL query values by default (section 12.2); data leaves the host only through sinks the admin configures | Decided (URL redaction), Proposed (rest) |
| NFR-13 | Portability | Prebuilt binaries for `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc` | Implemented (archives) |
| NFR-14 | Build | Minimum Rust version follows the dependencies: 1.89 now, raised only when a dependency needs it (expected 1.98 with the eBPF sensor); CI builds with exactly that version | Decided |
| NFR-15 | Quality | Coverage ≥ 80% for `core`, `enrich`, `storage-*` and the policy engine; ≥ 60% overall | Proposed (today 5% of product code) |
| NFR-16 | Extensibility | New backends and sensors must pass their conformance suites | Implemented |

## 6. Entry points

### 6.1 `scribed` (daemon)

Started by the service manager as root / SYSTEM: systemd unit `scribed` (Linux), launchd `com.scribe.daemon` (macOS), Windows service `scribed` (all proposed names).

| Invocation | Effect | Status |
|---|---|---|
| `scribed` | Run the service: load config, start logging, open storage, wait for a stop signal. Capture and storage writing arrive in phases 1–5 | Implemented (no capture yet) |
| `scribed --version`, `-V` | Print `scribed <version>` | Implemented |
| `scribed --config <path>` | Use this config file | Implemented |
| `scribed --check-config` | Print the effective config (absolute paths, resolved percentages) and exit | Implemented |
| SIGHUP (Linux, macOS) | Reload the config, same as `scribe daemon reset --config` | Planned (phase 5) |
| SIGTERM / Ctrl-C / service stop | Flush sinks and shut down cleanly | Implemented for Ctrl-C and SIGTERM; service-manager stop in phase 5 |

### 6.2 `scribe` (CLI)

Talks to `scribed` through the local API.

| Command | Effect | Status |
|---|---|---|
| `scribe version`, `--version`, `-V` | Print `scribe <version>` | Implemented |
| `scribe status` | Short form of `scribe daemon status` (section 6.2.1) | Stub |
| `scribe hosts` | Tracked hosts with counters and flags | Stub |
| `scribe mode <learn\|caution\|alert>` | Switch mode | Stub (mode name checking works) |
| `scribe alerts` | List alerts | Planned |
| `scribe alerts ack <id>` | Acknowledge an alert | Planned |
| `scribe baseline add\|rm <host>` | Edit the active profile's baseline | Planned |
| `scribe export` | Dump hosts and baseline | Stub |
| `scribe daemon <command>` | Inspect and control the running daemon (section 6.2.1) | Planned |

Exit codes: `0` success, `1` failure (including "not implemented yet"), `2` usage error. `scribed` uses the same codes, with `2` also for configuration errors.

#### 6.2.1 `scribe daemon` subcommands

Commands that look at or steer the running `scribed` itself, rather than the data it collects. All of them
are **Planned** for phase 10, on daemon support built in phase 5 (section 8.5). Every command fails with
exit code `1` and the message *scribed is not running or its socket is not reachable* when the daemon
can't be reached. `status` and `health` take `--json` for scripts.

| Command | Effect | Access |
|---|---|---|
| `scribe daemon status [--json] [--watch <interval>]` | Current state and live counters: run state (`running`, `degraded`, `hibernating` with since / until), version, uptime, config path and load time, mode and profile (learn time left), sensor kind and process attribution, flows/s and events/s over the last minute, flows, hosts, new hosts and alerts since start or last reset, pipeline queue depth. Per sink: healthy, last write, lag, spool size and drops. Host cache entries / limit and hit rate; state-store buffer use and drops; daemon memory and CPU. **Critical metrics** are listed first and highlighted: any drops, an unhealthy sink, spool or buffer over 80% of its limit, a fallback sensor, hibernation. `--watch` redraws every interval (e.g. `2s`) | Read (`scribe` group) |
| `scribe daemon health [--json] [--timeout <duration>]` | Basic health check for scripts, monitoring and service managers. Prints `healthy`, `degraded: <reasons>` or `unhealthy: <reasons>`. Exit `0` for healthy or degraded, `1` for unhealthy or unreachable. Default timeout `2s`. Checks: the API answers, the pipeline is moving, the sensor is attached (or the daemon is hibernating on purpose), the state store is writable | Read (`scribe` group) |
| `scribe daemon reset [--counters] [--caches] [--config]` | Runtime reset. With no flag it does all three. `--counters`: zero the runtime counters shown by `status` (rates, drop counts, totals since reset); **stored host counters and history are never touched**. `--caches`: write pending batches to storage first, then clear the host cache and the DNS (IP → name) cache; both refill from the state store and new DNS answers. `--config`: re-read the config file and apply it (section 8.5.2); an invalid file is rejected with its line and column, the running config stays and the command exits `1`. Prints what was reset and any settings that need a restart | Control (`scribe-admin` group) |
| `scribe daemon hibernate [--for <duration>]` | Stop processing: detach the sensor, write pending batches, stop scoring and alerting. The daemon keeps running and answers the API. With `--for` (e.g. `30m`) it wakes up on its own. Already hibernating: reports since when, exit `0` (with `--for`, sets the new wake-up time) | Control (`scribe-admin` group) |
| `scribe daemon wakeup` | Resume processing: reattach the sensor and continue with the same mode, baseline and caches. Already running: says so, exit `0` | Control (`scribe-admin` group) |

`scribe status` stays as a short form of `scribe daemon status` (same output) because it's the command
people type first. The CLI spells the command `hibernate`; `hybernate` and `sleep` are accepted as aliases,
and `wake` as an alias of `wakeup` (Proposed).

### 6.3 Local API

gRPC (`tonic`) over a Unix socket (Linux, macOS) or named pipe (Windows); **Planned**. Its calls follow the CLI and the UI mock data in `ui/tests/mocks/api-scenarios/`:
status, list hosts (paged, filtered), list / stream alerts, acknowledge alert, set mode, get / edit baseline, export, and the daemon controls `Health`, `Reset` (targets: counters, caches, config), `Hibernate` (optional duration) and `Wakeup`. `Health` is also served through the standard gRPC health protocol (`grpc.health.v1`, `tonic-health`) so generic tools can probe it. The API reports `api_version` so the UI can detect a mismatch.

Access (Proposed, extends NFR-9): the daemon checks the caller's identity from the socket (`SO_PEERCRED` on Linux, `getpeereid` on macOS, the named-pipe client token on Windows). Read calls (status, health, hosts, alerts, export) are allowed to everyone who may open the socket (root / Administrators and the `scribe` group); control calls (`Reset`, `Hibernate`, `Wakeup`, set mode, acknowledge, baseline edits) only to root / Administrators and the `scribe-admin` group (group names Proposed). Every control call is logged with the caller, the call and the result, and stored as an `audit` event.

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
| Policy engine | `crates/policy` (`scribe-policy`), no I/O | Modes, scoring rules, dedupe, learn time limit | core, storage-api | Planned |
| Alert outputs | `crates/alerts` (`scribe-alerts`) | OS notifications, log, webhook | core | Planned (interface exists) |
| Local API | `crates/api` (`scribe-api`, features `server` / `client`) + `proto/scribe/v1/api.proto` | gRPC service and client | core, storage-api | Planned |
| Daemon | `crates/daemon` (`scribed`) | Wires everything; config, logging, service lifecycle | all of the above | Stub |
| CLI | `crates/cli` (`scribe`) | Command line client | core, API client | Partly |

### 7.2 Planned crates — layout (decided: option A)

| Option | Layout | For | Against |
|---|---|---|---|
| **A (chosen)** | `crates/policy` (`scribe-policy`), `crates/alerts` (`scribe-alerts`), `crates/api` (`scribe-api`, features `server` / `client`), protocol in `proto/scribe/v1/api.proto` | Matches the current one-crate-per-module layout; the CLI depends only on the `client` feature; each crate testable alone | Three more crates |
| B | Alert outputs inside `scribe-policy` (`policy::outputs`) | One crate fewer; the engine that decides also delivers | OS notification code (per-OS dependencies) mixed into otherwise pure decision logic, harder to test |
| C | API split: `scribe-api-proto` (generated types), server inside `scribed`, client crate for CLI and UI | Smallest client; server code lives with the daemon it serves | Generated code in its own crate; more crates than A |
| D | Everything inside `crates/daemon` as modules | No new crates | Daemon grows large; scenario tests can't run the policy engine without the whole daemon |

**Decision:** option A. It keeps the policy engine free of I/O, so the 11 scenarios can drive it directly with the test doubles, and the CLI and UI link only the API client. Options B–D are kept for the record.

### 7.3 Test and support modules (implemented)

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

| Reason | Signal | Score | Status |
|---|---|---|---|
| `raw_ip` | Connection to an IP with no DNS lookup before it | 60 | Draft default |
| `unusual_port` | Destination port not in `policy.usual_ports` | 30 | Draft default |
| `high_entropy` | Longest domain label ≥ 10 characters with Shannon entropy ≥ 3.5 bits/character | 50 | Draft default |
| `new_tld` | Top-level domain not seen before | 20 | Draft default |
| `new_process` | Process that never made network connections before | 25 | Draft default |
| `threat_list` | Host or IP in a configured threat list | 100 | Draft default |

- **Scoring:** the scores of all matching signals are added and capped at 100. Caution mode alerts when the total reaches `policy.threshold` (default **50**), and the alert names the highest-scoring signal. A score of 0 disables a signal.
- **Usual ports:** TCP 22, 53, 80, 443, 465, 587, 853, 993, 995; UDP 53, 123, 443, 853, 5353.
- **Threat lists:** none by default, because fetching a list is itself outgoing traffic. Lists can be local files or URLs with a refresh interval, in `domains`, `hosts` or `ips` format.
- **Check against the scenarios:** an ordinary new host scores 25 (`new_process`) and stays quiet; the raw-IP case scores 60 + 30 + 25 and alerts as `raw_ip`; the random-looking domain scores 50 + 20 + 25 and alerts as `high_entropy`. This matches `caution-ordinary-new-host`, `caution-raw-ip`, `caution-high-entropy-domain` and `learn-auto-switch`.

### 8.4 Degraded operation

| Situation | Behaviour | Status |
|---|---|---|
| Native sensor unavailable (old kernel, extension not approved) | Fall back to the pcap sensor; status reports no process info | Planned |
| Event sink down | Spool to disk (`storage.spool`), replay in order; when `max_size` or `min_free_disk` is reached drop the oldest and count drops | Draft default |
| State store unavailable | Keep the latest events in an in-memory buffer (`storage.buffer`); when full, drop the oldest to add the newest; count drops, report unhealthy, replay in order on recovery (FR-25) | Decided |
| Hostname hidden (ECH, DoH) | Track by IP or outer name, flag it | Planned |
| Invalid config | At start: refuse to start, report the error and line (Implemented). On reload: keep the running config, report the error and line (Planned) | Partly |

### 8.5 Daemon run states (Planned, phase 5)

```
starting ──▶ running ◀──(health checks)──▶ degraded
                │  ▲
     hibernate  │  │  wakeup / --for elapsed
                ▼  │
             hibernating
any ──(SIGTERM, Ctrl-C, service stop)──▶ stopping ──▶ stopped
```

- **running:** the full pipeline works. **degraded:** it works with a fallback or a fault (pcap sensor
  without process info, an event sink spooling, the state store buffering, drops counted).
  `degraded` is a health result, not a separate mode; hibernation can be entered from either.
- **hibernating:** the sensor is detached (eBPF programs and ETW sessions closed, pcap stopped), so it
  costs no CPU and sees nothing. Pending batches are written, the spool keeps replaying to sinks that
  return, the API answers, retention keeps running. Flows during hibernation are **not recorded** and
  raise no alerts.
- **Visible gap:** entering and leaving hibernation writes a log entry and an `audit` event
  (`hibernate` / `wakeup` with the caller and the planned end) to the event sinks subscribed to it, so stored history shows
  the gap. `status` and `health` show `hibernating since … until …`.
- **Timers:** the `learn_for` countdown pauses while hibernating, so learn mode isn't cut short by a pause.
  The alert dedupe window keeps running on the clock.
- **Mode changes and baseline edits** are accepted while hibernating and apply after wakeup.
- **Restart:** hibernation doesn't survive a restart; `scribed` always starts in `running` (Proposed;
  the alternative of persisting it in the state store is open question 9).

#### 8.5.1 Counter reset

Runtime counters (rates, drop counts, totals since start) live in memory and back `status`. `reset --counters`
zeroes them and stamps `counters since <time>`. Stored per-host counters, hourly buckets and events are
history and are never changed by `reset`.

#### 8.5.2 Config reload

`reset --config` and SIGHUP re-read the same file `scribed` started with (the `--config` /
`SCRIBE_CONFIG` / OS default lookup isn't repeated), run the same checks as at start, and apply what can
change live:

| Applies live | Needs a restart (reported, not applied) |
|---|---|
| `mode`, `learn_for`, `then`, `profile`; all of `[policy]` (scores, threshold, usual ports, entropy, threat lists); `privacy.url_query`; `[log] level` and `format`; alert outputs; sink retention and batching; cache, buffer and spool limits (shrinking drops the oldest entries) | `data_dir`; the state store backend and its URL; adding or removing sinks; the sensor; `[log] file`, `output` and `rotate`; the API socket |

A reload is all-or-nothing for the live settings: if the file fails any check, nothing changes.

## 9. Options

### 9.1 Config file (`scribed`)

TOML, config format version 1: [config/scribe.toml](../config/scribe.toml). The file lists every
option with its built-in default, so an empty file or no file behaves the same; a test enforces it.
Loaded and checked by `crates/daemon/src/config/` (phase 0).

**Value formats**
- **Duration:** `45s`, `10m`, `1h`, `7d`.
- **Size:** absolute (`512KiB`, `32MiB`, `2GiB`, 1024-based) or a percentage (`1%`). For memory limits a percentage means a share of total physical RAM; for disk limits, a share of the size of the volume holding the path. Percentages are resolved once at startup and logged.
- **Path:** relative paths resolve against `data_dir`.

**Choosing between percentages and absolute sizes:** absolute values are the default because they keep memory use predictable on any machine (NFR-3). Percentages suit fleets of very different machines; for those, keep percentages small (memory 1–2%, spool 2–5% of the volume) and watch the resolved values in the startup log.

| Key | Type | Default | Status |
|---|---|---|---|
| `version` | integer | `1` | Draft default |
| `mode` | `learn` \| `caution` \| `alert` | `learn` | Decided |
| `profile` | string | `default` | Decided |
| `data_dir` | path | OS default (below) | Decided |
| `[policy] learn_for` | duration, `""` = no limit | `""` | Draft default |
| `[policy] then` | `caution` \| `alert` | `caution` | Draft default |
| `[policy] dedupe_window` | duration | `10m` | Draft default |
| `[policy] threshold` | 0–100 | `50` | Draft default |
| `[policy.scores] raw_ip`, `unusual_port`, `high_entropy`, `new_tld`, `new_process`, `threat_list` | 0–100 | 60, 30, 50, 20, 25, 100 | Draft default |
| `[policy.usual_ports] tcp`, `udp` | port lists | section 8.3 | Draft default |
| `[policy.entropy] min_label_length`, `min_bits_per_char` | integer, number | `10`, `3.5` | Draft default |
| `[[policy.threat_lists]] name`, `path` or `url`, `format`, `refresh` | — | none | Draft default |
| `[privacy] url_query` | `full` \| `redact_values` \| `strip` \| `path_only` \| `hash` | `redact_values` | Decided (section 12.2) |
| `[storage.state] kind` | `sqlite` \| `postgres` | `sqlite` | Decided |
| `[storage.state] path` (SQLite) | path | `state.db` | Draft default |
| `[storage.state] url`, `credentials` (Postgres) | URL without password; secret reference (`keychain:`, `dpapi:`, `secret-service:`, `file:`) | — | Decided / Proposed |
| `[storage.cache] max_hosts` | integer | `50000` | Draft default |
| `[storage.cache] max_memory` | size or % of RAM | `32MiB` | Draft default |
| `[storage.buffer] max_events` | integer | `50000` | Draft default |
| `[storage.buffer] max_memory` | size or % of RAM | `32MiB` | Draft default |
| `[storage.spool] dir` | path | `spool` | Draft default |
| `[storage.spool] max_size` | size or % of volume | `512MiB` | Draft default |
| `[storage.spool] min_free_disk` | size or % of volume | `5%` | Draft default |
| `[[storage.sinks]] name` | string | `local-history` | Draft default |
| `[[storage.sinks]] kind` | `sqlite` \| `postgres` | `sqlite` | Decided |
| `[[storage.sinks]] path` / `url` / `credentials` | as above | `events.db` | Draft default |
| `[[storage.sinks]] events` | list of `flow`, `alert`, `audit`; `[]` = all | `[]` | Decided |
| `[[storage.sinks]] retention` | duration, `""` = forever | `30d` | Draft default |
| `[[storage.sinks]] batch_max_events`, `batch_max_wait` | integer, duration | `500`, `1s` | Draft default |
| `[log] level` | `error` … `trace` | `info` | Draft default |
| `[log] format` | `text` \| `json` | `text` | Draft default |
| `[log] output` | `file` \| `system` \| `both` | `file` | Decided |
| `[log] file` | path, used when `output` is `file` or `both` | OS default (below) | Decided |
| `[log] rotate`, `max_size`, `keep` | `daily` \| `size`, size, integer | `daily`, `50MiB`, `14` | Draft default |

When a cache, buffer or spool limit is hit, the oldest entries are dropped and the drop counters show in `scribe status`. The cache drops the least-recently-used hosts, which are re-read from the state store on demand.

**Default locations**

| OS | Config file | Data directory | Log file | System log (`log.output = "system"` or `"both"`) | Status |
|---|---|---|---|---|---|
| Linux | `/etc/scribe/scribe.toml` | `/var/lib/scribe/` | `/var/log/scribe/scribed.log` | journald / syslog | Decided |
| macOS | `/Library/Application Support/scribe/scribe.toml` | same folder | `/var/log/scribe/scribed.log` | unified logging | Decided |
| Windows | `<install dir>\scribe.toml` (next to `scribed.exe`) | `<install dir>\data\` | `<install dir>\logs\scribed.log` | Event Viewer (Applications and Services Logs\scribe) | Decided |

Precedence: `--config` flag, then `SCRIBE_CONFIG`, then the OS default; with no file, built-in defaults. A file named by the flag or the variable must exist (implemented).

**Notes on the Windows choices**
- Config, data and the log file all live next to the app; logs go to the Event Viewer instead when `log.output = "system"` (decided).
- Consequence for packaging (phase 13): the MSI must never overwrite or delete `scribe.toml`, `data\` and `logs\` on upgrade or uninstall (mark them permanent / never-overwrite), and must give the service account write access to `data\` and `logs\`, since `Program Files` is read-only for everyone else.
- Alternative if that proves awkward: `%ProgramData%\scribe\`, Windows' standard location for machine-wide config, data and logs.
- On macOS, Apple's own convention for system-wide app logs is `/Library/Logs/scribe/`; `/var/log/scribe/` works equally and matches Linux.

### 9.2 Environment variables

| Variable | Used by | Purpose | Status |
|---|---|---|---|
| `SCRIBE_CONFIG` | `scribed` | Config file path (after `--config`, before the OS default) | Implemented |
| `SCRIBE_LOG` | `scribed` | Log filter, `RUST_LOG` syntax; overrides `[log] level`; an invalid filter exits with 2 | Implemented |
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

### 12.1 Security

- Capture needs root / SYSTEM, an approved Network Extension (macOS), or Npcap (Windows). The daemon should drop privileges once the sensor runs (NFR-8).
- Every parser reads untrusted bytes and is fuzzed (NFR-11).
- Only metadata is stored, never payloads (NFR-12).
- Data stays on the host unless the admin configures a remote sink; credentials never sit in plain config (NFR-10).
- Test data never contains real user traffic; only documentation address ranges and `example.com` / `example.net` names.

### 12.2 URL privacy (`privacy.url_query`)

**Decision:** default `redact_values` (FR-26).

**Why it matters.** For plaintext HTTP, scribe sees the full URL. Query strings often carry tokens,
session ids, user ids or personal search terms. Stored as-is, they would sit in the local database
and in every event sink, including a central PostgreSQL. `privacy.url_query` decides how much of
the URL is kept.

**Rules that apply to every option**
- Only plaintext HTTP URLs are seen; for HTTPS scribe knows only the host name.
- Scheme and host are always kept.
- User info (`user:password@`) is always removed, even with `full`.
- Fragments (`#…`) are never sent by clients, so they never appear.
- Alerts, events and `scribe hosts` all show the URL in the same stored form.
- Changing the option applies to new data only; URLs already stored are not rewritten.

**Options**

| Option | Rule | Keeps | Loses |
|---|---|---|---|
| `full` | URL as seen, minus user info | everything; best for forensics | privacy: tokens and personal data reach every database and sink |
| **`redact_values`** (default) | Every query value becomes `<redacted>`; keys, their order and repeats are kept; a key with no value (`safe`) or an empty value (`q=`) stays as is | path and parameter names: enough to recognise what an app does | parameter values; ids inside the **path** remain visible |
| `strip` | Query removed | full path | which parameters were sent |
| `path_only` | First path segment kept, rest replaced by `…`; query removed | rough area of the site | most of the path |
| `hash` | Query replaced by `?<hash:xxxxxx>`, a keyed hash of the whole query (HMAC-SHA256 with a per-install secret key, first 6 hex digits, computed with `ring`) | lets repeated requests be matched without storing values | readability; matching only works on the same install and while the key is unchanged |

The `hash` key is generated on first start and stored in `data_dir` readable only by the service account (proposed: `url_hash.key`). Without it, a hash of a short value such as a user id could be reversed by trying likely values.

**Examples**

1. Simple query
   ```
   seen           http://plain.example.com/download?id=42
   full           http://plain.example.com/download?id=42
   redact_values  http://plain.example.com/download?id=<redacted>
   strip          http://plain.example.com/download
   path_only      http://plain.example.com/download
   hash           http://plain.example.com/download?<hash:3f9c1e>
   ```
2. Token in the query, user id in the path
   ```
   seen           http://api.example.com/v1/users/1234/profile?token=eyJhbGciOiJIUzI1NiJ9.e30.Zm9v&lang=en
   full           http://api.example.com/v1/users/1234/profile?token=eyJhbGciOiJIUzI1NiJ9.e30.Zm9v&lang=en
   redact_values  http://api.example.com/v1/users/1234/profile?token=<redacted>&lang=<redacted>
   strip          http://api.example.com/v1/users/1234/profile
   path_only      http://api.example.com/v1/…
   hash           http://api.example.com/v1/users/1234/profile?<hash:a41f9c>
   ```
   Only `full` keeps the token, a live credential. Only `path_only` also hides the id `1234` in the path.
3. Login details in the URL
   ```
   seen           http://admin:s3cret@intranet.example.com/reports/2026/q3.pdf?print=1
   full           http://intranet.example.com/reports/2026/q3.pdf?print=1
   redact_values  http://intranet.example.com/reports/2026/q3.pdf?print=<redacted>
   strip          http://intranet.example.com/reports/2026/q3.pdf
   path_only      http://intranet.example.com/reports/…
   hash           http://intranet.example.com/reports/2026/q3.pdf?<hash:07d2b8>
   ```
   `admin:s3cret@` is removed under every option.
4. No query
   ```
   seen           http://cdn.example.net/assets/js/app.js
   full           http://cdn.example.net/assets/js/app.js
   redact_values  http://cdn.example.net/assets/js/app.js
   strip          http://cdn.example.net/assets/js/app.js
   path_only      http://cdn.example.net/assets/…
   hash           http://cdn.example.net/assets/js/app.js
   ```
5. Personal search terms, a parameter without a value
   ```
   seen           http://search.example.com/?q=my+medical+condition&page=2&safe
   full           http://search.example.com/?q=my+medical+condition&page=2&safe
   redact_values  http://search.example.com/?q=<redacted>&page=<redacted>&safe
   strip          http://search.example.com/
   path_only      http://search.example.com/
   hash           http://search.example.com/?<hash:c90e44>
   ```
6. Tracking pixel: repeated parameter, encoded URL as a value
   ```
   seen           http://tracker.example.net/pixel.gif?uid=8f3a2c&uid=8f3a2c&ref=http%3A%2F%2Fshop.example.com%2Fcart
   full           http://tracker.example.net/pixel.gif?uid=8f3a2c&uid=8f3a2c&ref=http%3A%2F%2Fshop.example.com%2Fcart
   redact_values  http://tracker.example.net/pixel.gif?uid=<redacted>&uid=<redacted>&ref=<redacted>
   strip          http://tracker.example.net/pixel.gif
   path_only      http://tracker.example.net/pixel.gif
   hash           http://tracker.example.net/pixel.gif?<hash:5b17ad>
   ```
   Under `hash`, the same request from the same install always gives `5b17ad`, so repeats can be counted without storing the user id.

(Hash values above are illustrative.)

**What each option still lets you answer**

| Question | `full` | `redact_values` | `strip` | `path_only` | `hash` |
|---|---|---|---|---|---|
| Which endpoint was called? | yes | yes | yes | roughly | yes |
| Which parameters were sent? | yes | yes | no | no | no |
| What were the values? | yes | no | no | no | no |
| Is this the same request as before? | yes | partly | no | no | yes |
| Can secrets reach storage or a central sink? | **yes** | only via the path | only via the path | rarely | no |

**Why `redact_values` is the default:** it shows what an application does (endpoint and parameter
names) without keeping values, which is where tokens and personal data usually are. Use `full` only on
machines where forensics outweighs privacy and no remote sink is configured; use `path_only` where
paths themselves carry ids.

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
| Daemon controls (FR-27 – FR-31) | Daemon tests with `FakeSensor`, `FakeClock`, `FaultySink`; CLI tests against `MockApiServer`; mocks `daemon-down`, `daemon-restart`; sensor conformance case *stop, then start again* | Planned |
| Install and upgrade (UC-10) | End-to-end scripts | Yes (need installers) |
| Non-functional (NFR-1 – NFR-5) | Performance and soak runs | Planned |

## 15. Open questions

| # | Question | Answer / state |
|---|---|---|
| 1 | Minimum Rust version | **Answered:** policy *follow dependencies*; 1.89 now, 1.98 expected for the eBPF sensor (NFR-14) |
| 2 | Default config and data paths per OS | **Answered:** OS defaults on Linux and macOS; on Windows config next to the app (`<install dir>\scribe.toml`); data `<install dir>\data\` (section 9.1) |
| 3 | Scores, threshold, usual ports, threat lists | **Answered:** draft v1 config [config/scribe.toml](../config/scribe.toml) with all defaults (section 8.3) |
| 4 | Behaviour when the state store is unavailable | **Answered:** in-memory buffer of the latest events, oldest dropped on overflow (FR-25) |
| 5 | Host cache and spool size limits | **Answered:** `storage.cache`, `storage.buffer`, `storage.spool`, absolute or percentage (section 9.1) |
| 6 | Whether to strip query strings from stored URLs | **Answered:** `privacy.url_query`, default `redact_values` (section 12.2) |
| 7 | Names and locations of the policy engine, alert outputs and local API crates | **Answered:** option A — `crates/policy`, `crates/alerts`, `crates/api` + `proto/scribe/v1/api.proto` (section 7.2) |
| 8 | Log locations | **Answered:** `/var/log/scribe/` on Linux and macOS (system log optional); on Windows a file next to the app, or the Event Viewer when configured (`log.output`, section 9.1) |
| 9 | Should hibernation survive a restart of `scribed`? | **Open.** Proposed: no, a restart always resumes processing, so a forgotten pause can't silence monitoring for good; `--for` covers planned windows (section 8.5) |
| 10 | Names: `hibernate` / `wakeup` with aliases `hybernate`, `sleep`, `wake`; `scribe status` kept as short form of `scribe daemon status` | **Proposed** (section 6.2.1) |

## 16. References

- [plan.md](plan.md) — phases, estimates, milestones, risks
- [diagram.md](diagram.md) — components, connection flow, mode decision, storage plugin classes
- [status.md](status.md) — completion and coverage per module
- [test-approach.md](test-approach.md) — test levels and tooling
- [scribe-conventions skill](../.claude/skills/scribe-conventions/SKILL.md) — decided values
- [readme.md](../readme.md) — overview, build, versioning, workflows
