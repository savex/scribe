# scribe specification

*Version 0.10 (draft), 2026-11-22: storage manager implemented (phase 2, section 10.5). 0.9: SQLite backend implemented (phase 1). 0.8: module framework implemented (phase 0b); section 7.4 records what was built and five refinements (7.4.9). 0.7: adds the module framework (section 7.4) with URL tracking as the first module and kernel metrics as the example of a later one. 0.6: security design carried into the daemon commands, API, run states, config keys, verification and open questions. 0.5: adds the security design for every interaction (section 12.1, all Proposed). 0.4: adds the `scribe daemon` subcommands (status, health, reset, hibernate, wakeup) and the daemon run states. 0.3: all open questions answered; phase 0 (config, logging, daemon lifecycle, CLI parsing) implemented.*
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
| Module | A compiled-in feature of `scribed` that plugs into the pipeline through `scribe-module-api` (section 7.4): URL tracking now, kernel metrics and others later |
| Flow note | A module's typed value attached to a flow, e.g. the URL of a plaintext HTTP request |

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
A developer adds a storage backend by implementing `StorageFactory` plus `StateStore` and / or `EventSink`, a sensor by implementing `Sensor`, or a module (new functionality such as kernel metrics) by implementing `Module`. It's accepted only after passing `scribe-storage-conformance`, `scribe-sensor-conformance` or `scribe-module-conformance`.

### UC-12 Check and control the running daemon
1. Monitoring or a service manager runs `scribe daemon health` every minute and acts on exit code `1`.
2. The admin runs `scribe daemon status` to see why: drops, an unhealthy sink, a full spool, a fallback sensor.
3. After editing `scribe.toml` the admin applies it with `scribe daemon reset --config` (or SIGHUP), without losing the pipeline state; `scribe daemon reset --counters` starts a clean measurement window.
4. For a planned maintenance window or a noisy test, the admin runs `scribe daemon hibernate --for 1h`; scribe records nothing and alerts on nothing until `scribe daemon wakeup` or the hour is over. The gap is visible in `status`, the log and the stored history.

## 5. Requirements

### 5.1 Functional

| ID | Requirement | Status | Verified by |
|---|---|---|---|
| FR-1 | Capture every outgoing TCP connection and UDP / QUIC flow, IPv4 and IPv6, on macOS, Linux and Windows | Partly (pcap sensor on every OS, verified live on Linux; native sensors in phases 7–9) | Sensor conformance suite; pcap fixtures |
| FR-2 | Attribute each flow to its process (pid and path) where the sensor allows; the pcap fallback reports no process | Partly (the pcap fallback reports no process; native sensors in phases 7–9) | Sensor conformance (`expect_process_info`) |
| FR-3 | Find the host name in this order: TLS SNI, HTTP `Host` header, DNS cache (IP → queried name, CNAME chains map back to the queried name) | Implemented (`scribe_enrich::Enricher`; a name the sensor reports ranks after `Host`; wired to traffic in phase 5) | pcap fixtures `tls13_sni_ipv4`, `http_plain`, `dns_cname_then_tls`, `dns_aaaa_then_tls` |
| FR-4 | Classify each flow as `tls`, `quic`, `plaintext` or `unknown` from its first bytes, never from the port | Implemented (TCP and UDP, QUIC long headers) | Functional tests in `enrich`; every fixture end to end |
| FR-5 | For ECH, record the outer public name and flag the flow `ech` | Implemented | Fixture `tls_ech` |
| FR-6 | For QUIC, read the SNI from the Initial packet (using `ring` 0.17) | Implemented (v1 and v2, ClientHello across several Initials; per-flow reassembly wired in phase 5) | RFC 9001 and RFC 9369 Appendix A packets; fixtures `quic_initial`, `quic_split_hello`; fuzz target `quic_initial` |
| FR-7 | Track hosts without a name by IP, flagged unresolved; never drop them | Implemented (hosts keyed by IP when nameless, `hosts.unresolved` since schema v3; shown by `scribe hosts` in phase 10) | Scenario `hostname-unresolved`; fixture `doh` |
| FR-8 | Record the full URL for plaintext HTTP requests (URL module, section 7.4.6) | Implemented (request parser, all `query` modes including `hash`; wired to traffic in phase 5) | Fixture `http_plain`; module conformance |
| FR-9 | Keep connection, request and byte counters per host and per process + host, plus hourly buckets; updates are deltas | Implemented (per host and per process + host since schema v3; hourly buckets per host since schema v4) | Scenario `counters-exact`; storage conformance |
| FR-10 | Keep each host's first seen, last seen, `tls_seen` and `plaintext_seen` (flags only turn on) | Implemented in the SQLite state store (Postgres in phase 12) | Storage conformance |
| FR-11 | Support the modes `learn`, `caution` and `alert` with the behaviour in section 8 | Implemented (`scribe-policy`; fed by the pipeline in phase 5) | Scenarios |
| FR-12 | Support time-limited learn mode that switches to a chosen mode | Implemented (pausing the timer while hibernating arrives with phase 5) | Scenario `learn-auto-switch` |
| FR-13 | Keep baselines per profile with learned / manual entries; add and remove entries | Partly (stored per profile with learned / manual entries in SQLite; the policy adds and removes entries in memory; saving them and the commands arrive in phases 5 and 10) | Storage conformance; scenarios |
| FR-14 | Score unlisted hosts with the non-ordinary rules and report the reason | Implemented (built-in and module signals, threat lists from files) | Caution scenarios |
| FR-15 | Deduplicate alerts per host + process within a window; support acknowledging | Implemented in the engine (saving the alert state arrives in phase 5) | Scenario `alert-dedupe-window` |
| FR-16 | Deliver alerts as OS notifications, log entries and optional webhook calls | Planned | `RecordingAlertSink` in daemon tests |
| FR-17 | Store state in exactly one state store and events in zero or more event sinks, each subscribed to event kinds | Implemented (state store behind cache and outage buffer; sinks by subscribed kind through writer tasks) | Storage conformance; manager tests (planned) |
| FR-18 | Provide SQLite (default) and PostgreSQL (feature `postgres`) backends | Partly (SQLite implemented and conformant; PostgreSQL in phase 12) | Storage conformance; Tests workflow |
| FR-19 | Spool events when a sink fails and replay them in order; enforce per-sink retention | Implemented (spool and ordered replay, retention via `delete_before`) | `FaultySink` tests (planned) |
| FR-20 | Expose a local API for the CLI and UI, including runtime mode changes | Implemented (phase 10) | API integration tests (INT-13), CLI against a daemon (INT-12) and against `MockApiServer` (SCN-UI) |
| FR-21 | Provide the CLI commands in section 6.2 | Partly (all commands parsed; only `version` works until the API exists) | `scribe-cli` unit and binary tests |
| FR-22 | Load and validate a TOML config file; report errors with line numbers | Implemented | `scribe-daemon` config tests; shipped file equals built-in defaults |
| FR-23 | Report the version from the nearest git tag (`scribe --version`, `scribed --version`) | Implemented | Release workflow smoke check |
| FR-24 | Export hosts and baselines | Planned | — |
| FR-25 | While the state store is unavailable, keep the latest events in a bounded in-memory buffer; when full, drop the oldest to add the newest; count drops; replay in order on recovery | Implemented (`BufferedState`) | `FaultySink`-style state-store tests (planned) |
| FR-26 | Store plaintext URLs according to `[modules.url] query` (formerly `privacy.url_query`); always remove user info (`user:password@`) | Planned | Unit tests (planned); fixture `http_plain` |
| FR-27 | `scribe daemon status` shows the run state, live counters and critical metrics (section 6.2.1); `scribe status` is its short form | Implemented (phase 10) | API tests; CLI output tests; SCN-UI with `MockApiServer` |
| FR-28 | `scribe daemon health` reports healthy / degraded / unhealthy with reasons, exits `0` / `1`, and answers within its timeout; also over `grpc.health.v1` | Planned (phase 10; the parts exist: storage health, run state, sensor start result) | Daemon tests with `FaultySink` and a stopped `FakeSensor`; mock `daemon-down` |
| FR-29 | `scribe daemon reset` clears runtime counters and caches and reloads the config without a restart; never changes stored history; an invalid config is rejected and the running one kept | Implemented in the daemon (`Command::Reset`, `Command::Reload`, SIGHUP; the command in phase 10) | Daemon tests; config error table reused for reload |
| FR-30 | `scribe daemon hibernate [--for]` stops capture and processing while the daemon keeps serving the API; the pause is capped by `daemon.max_hibernate`, raises an alert, and is recorded and visible | Implemented in the daemon (`Pipeline::hibernate`, `Command::Hibernate`; the command in phase 10) | Daemon tests with `FakeSensor` and `FakeClock`; sensor conformance (stop and start again) |
| FR-31 | `scribe daemon wakeup` (or the end of `--for`) resumes processing with the same mode, baseline and caches | Implemented in the daemon (`Pipeline::wakeup`, timer wakeup on the 1 s tick; the command in phase 10) | Same as FR-30 |
| FR-32 | Load features as compiled-in modules through a registry; enable them with `[modules] enabled`; a module that isn't built or enabled costs nothing at run time | Implemented (registry, `url` feature, `[modules] enabled`) | Module conformance; daemon tests |
| FR-33 | Modules produce data only through the generic outputs: flow notes, module records, metric samples and module state (section 7.4.3) | Implemented (interfaces, in-memory doubles, schema v2; backends store them in phases 1 and 12) | Storage and module conformance |
| FR-34 | Modules may add an API service and CLI subcommands; `scribe modules` lists modules with version, state and health; calls to a module that isn't enabled fail clearly | Implemented (phase 10: `scribe url list`) | INT-12 (`module_subcommands_reach_the_module_service`, `a_module_that_is_not_enabled_is_named`); FUN-API03 |
| FR-35 | Modules follow the daemon run states: paused by `hibernate`, resumed by `wakeup`, reconfigured by `reset --config` | Partly (pause, resume, reconfigure in `ModuleHost`; `hibernate`, `wakeup`, `reset` arrive in phase 5) | Module conformance (pause / resume, reload) |

### 5.2 Non-functional

| ID | Requirement | Target | Status |
|---|---|---|---|
| NFR-1 | Throughput | 1,000 new connections/s | Proposed |
| NFR-2 | CPU overhead | < 2% of one core at NFR-1 | Proposed |
| NFR-3 | Memory | Daemon < 100 MB; the default cache (32 MiB) and buffer (32 MiB) budgets fit inside it | Proposed |
| NFR-4 | Latency | Flow to database p99 < 1 s; sensor reports each flow within 1 s | Proposed (1 s sensor deadline is decided) |
| NFR-5 | Stability | 24 h soak with flat memory, no handle leaks, empty spool | Proposed |
| NFR-6 | Durability | Restart keeps hosts, counters, baselines and mode; sink outages lose no events within the spool cap | Partly (state, counters, baselines and module state survive restarts in SQLite; the spool survives restarts; mode in phase 5)
| NFR-7 | Isolation | A slow or failing sink never blocks capture or other sinks | Implemented (writer task per sink; full queues drop and count)
| NFR-8 | Privileges | Runs as root / SYSTEM only as long as the sensor needs; drops privileges after start | Proposed |
| NFR-9 | API access | Local socket / named pipe only; caller identity from the OS; read calls for the `scribe` group, control calls for root / Administrators and `scribe-admin`, all control calls audited; clients verify the server (sections 6.3, 12.1.1) | Proposed |
| NFR-10 | Secrets | Database credentials, TLS client keys, the webhook secret, the URL hash key and the optional storage key from the OS keychain, DPAPI, Secret Service or a root-only file; never in plain config; startup refused when config, `data_dir` or a `file:` credential is group / other-writable | Implemented (`scribe-secrets`: `file:` references with mode checks, macOS keychain, Windows DPAPI, Linux Secret Service; `scribed --set-secret`); Windows ACL checks with the installer (phase 13) |
| NFR-11 | Robust parsing | Packet parsers never crash or hang on malformed input; fuzzed, crash-free for 7 runs in a row before release | Planned |
| NFR-12 | Privacy | Store connection metadata only, never payloads; redact URL query values by default (section 12.2); data leaves the host only through sinks the admin configures | Decided (URL redaction), Proposed (rest) |
| NFR-13 | Portability | Prebuilt binaries for `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc` | Implemented (archives) |
| NFR-14 | Build | Minimum Rust version follows the dependencies: 1.89 now, raised only when a dependency needs it (expected 1.98 with the eBPF sensor); CI builds with exactly that version | Decided |
| NFR-15 | Quality | Coverage ≥ 80% for `core`, `enrich`, `storage-*` and the policy engine; ≥ 60% overall | Proposed (today 5% of product code) |
| NFR-16 | Extensibility | New backends, sensors and modules must pass their conformance suites | Implemented |
| NFR-17 | Transport security | Everything that leaves the host (Postgres sink, webhook, threat lists) uses TLS with certificate verification; plaintext only to loopback | Partly implemented (`scribe-net` for webhooks: OS verifier or pin, loopback-only http; threat lists step 5, Postgres phase 12) |
| NFR-18 | Tamper evidence | Audit and alert records are hash-chained; hosts send heartbeats to the remote sink, so stopped daemons and deleted rows are visible | Partly (chain, start / stop / unclean-stop audits since phase 5; heartbeats with the remote sink in phase 12) |
| NFR-19 | Release integrity | Release checksums signed, build provenance attested, dependencies checked by `cargo deny` / `cargo audit` | Proposed |
| NFR-20 | Module isolation | A slow, failing or panicking module never blocks capture, storage or other modules: per-flow time budget, bounded queues with counted drops, a panic disables only that module and reports degraded health | Implemented in `ModuleHost` (budget counting, panic isolation, bounded output queue); per-module flow queues for slow hooks arrive with the pipeline (phase 5) |

## 6. Entry points

### 6.1 `scribed` (daemon)

Started by the service manager as root / SYSTEM: systemd unit `scribed` (Linux), launchd `com.scribe.daemon` (macOS), Windows service `scribed` (all proposed names).

| Invocation | Effect | Status |
|---|---|---|
| `scribed` | Run the service: load config, start logging, open storage, wait for a stop signal. Capture and storage writing arrive in phases 1–5 | Implemented (no capture yet) |
| `scribed --version`, `-V` | Print `scribed <version>` | Implemented |
| `scribed --config <path>` | Use this config file | Implemented |
| `scribed --check-config` | Print the effective config (absolute paths, resolved percentages) and exit | Implemented |
| `scribed --set-secret <reference> [--generate]` | Store a secret read from standard input (or, with `--generate`, a new random key printed once) in `file:`, `keychain:`, `dpapi:` or `secret-service:`; for webhook secrets and other credentials | Implemented (phase 11) |
| SIGHUP (Linux, macOS) | Reload the config, same as `scribe daemon reset --config` | Planned (phase 5) |
| SIGTERM / Ctrl-C / service stop | Flush sinks and shut down cleanly | Implemented for Ctrl-C and SIGTERM; service-manager stop in phase 5 |

### 6.2 `scribe` (CLI)

Talks to `scribed` through the local API: `--socket <path>` (global), else `SCRIBE_SOCKET`, else the OS
default (section 6.3). `--json` prints the API messages with their protocol field names.

| Command | Effect | Status |
|---|---|---|
| `scribe version`, `--version`, `-V` | Print `scribe <version>` (needs no daemon) | Implemented |
| `scribe status [--json] [--watch <interval>]` | Short form of `scribe daemon status` (section 6.2.1) | Implemented (phase 10) |
| `scribe hosts [--filter <text>] [--json]` | Tracked hosts with counters, what was seen (`tls`, `plain`), flags (`listed`, `unresolved`, `ech`) and processes | Implemented (phase 10; `ech` stays off until host records keep it) |
| `scribe mode <learn\|caution\|alert>` | Switch mode; prints `mode: <old> -> <new>` | Implemented (phase 10) |
| `scribe alerts [--json]` | List alerts (id = chain sequence), with their notes (e.g. the URL) below each | Implemented (phase 10) |
| `scribe alerts ack <id>` | Acknowledge an alert; acknowledging twice says so and exits `0` | Implemented (phase 10) |
| `scribe baseline [--json]` | List the active profile's baseline | Implemented (phase 10) |
| `scribe baseline add\|rm <host>…` | Edit the active profile's baseline (`remove` alias); prints added / removed / unchanged | Implemented (phase 10) |
| `scribe export [-o <file>]` | Hosts and baseline as one JSON document, to stdout or a file the CLI creates `0600` as the caller | Implemented (phase 10) |
| `scribe alerts --watch [--json]` | New alerts as they are raised, one line (or JSON object) each, until Ctrl-C | Implemented (phase 11) |
| `scribe notify [--max-per-minute 10] [--min-score 0] [--print]` | Desktop-notification agent for the user's session (started at login, `packaging/`): follows the alert stream, one notification per alert, the rest of a minute as one summary; `hibernated` always shown; waits while scribed is down and shows missed alerts after a reconnect; exits 1 only on permission denied or a failed server check | Implemented (phase 11) |
| `scribe daemon <command>` | Inspect and control the running daemon (section 6.2.1) | Implemented (phase 10) |
| `scribe modules [--json]` | Modules built into this `scribed`: id, version, enabled, state, health, over budget, drops | Implemented (phase 10) |
| `scribe <module> …` | Subcommands a module adds, e.g. `scribe url list [--host api.example.com] [--limit] [--since] [--json]`, later `scribe metrics show tcp.retrans`; exit `1` with *module url is not enabled in this scribed* when the daemon lacks it | Implemented (phase 10: `scribe url list`) |

Exit codes: `0` success, `1` failure (including "not implemented yet"), `2` usage error. `scribed` uses the same codes, with `2` also for configuration errors.

#### 6.2.1 `scribe daemon` subcommands

Commands that look at or steer the running `scribed` itself, rather than the data it collects. All of them
are **Implemented** (phase 10, on daemon support built in phase 5, section 8.5). Every command fails with
exit code `1` and the message *scribed is not running or its socket is not reachable* when the daemon
can't be reached. `status` and `health` take `--json` for scripts.

| Command | Effect | Access |
|---|---|---|
| `scribe daemon status [--json] [--watch <interval>]` | Current state and live counters: run state (`running`, `degraded`, `hibernating` with since / until), version, uptime, config path and load time, mode and profile (learn time left), sensor kind and process attribution, flows/s and events/s over the last minute, flows, hosts, new hosts and alerts since start or last reset, pipeline queue depth. Per sink: healthy, last write, lag, spool size and drops. Host cache entries / limit and hit rate; state-store buffer use and drops; daemon memory and CPU. **Critical metrics** are listed first and highlighted: any drops, an unhealthy sink, spool or buffer over 80% of its limit, a fallback sensor, hibernation. `--watch` redraws every interval (e.g. `2s`) | Read (`scribe` group) |
| `scribe daemon health [--json] [--timeout <duration>]` | Basic health check for scripts, monitoring and service managers. Prints `healthy`, `degraded: <reasons>` or `unhealthy: <reasons>`. Exit `0` for healthy or degraded, `1` for unhealthy or unreachable. Default timeout `2s`. Checks: the API answers, the pipeline is moving, the sensor is attached (or the daemon is hibernating on purpose), the state store is writable | Read (`scribe` group) |
| `scribe daemon reset [--counters] [--caches] [--config]` | Runtime reset. With no flag it does all three. `--counters`: zero the runtime counters shown by `status` (rates, drop counts, totals since reset); **stored host counters and history are never touched**. `--caches`: write pending batches to storage first, then clear the host cache and the DNS (IP → name) cache; both refill from the state store and new DNS answers. `--config`: re-read the config file and apply it (section 8.5.2); an invalid file is rejected with its line and column, the running config stays and the command exits `1`. Prints what was reset and any settings that need a restart | Control (`scribe-admin` group) |
| `scribe daemon hibernate [--for <duration>]` | Stop processing: detach the sensor, write pending batches, stop scoring and alerting. The daemon keeps running and answers the API. It always wakes up on its own: `--for` (e.g. `30m`) may not exceed `daemon.max_hibernate` (Proposed default `4h`), and without `--for` the maximum applies; there is no open-ended hibernation by default (section 12.1.1). Starting hibernation raises an alert (reason `hibernated`, with the caller and the planned end) through every alert output, whatever the mode. Already hibernating: reports since when, exit `0` (with `--for`, sets the new wake-up time, still capped) | Control (`scribe-admin` group) |
| `scribe daemon wakeup` | Resume processing: reattach the sensor and continue with the same mode, baseline and caches. Already running: says so, exit `0` | Control (`scribe-admin` group) |

The CLI refuses to talk to a server that isn't the real `scribed` (socket not owned by root, pipe server not running as SYSTEM) and exits `1` (section 12.1.1). Control commands run by a user outside `scribe-admin` exit `1` with *permission denied*, and the refusal is audited.

`scribe status` stays as a short form of `scribe daemon status` (same output) because it's the command
people type first. The CLI spells the command `hibernate`; `hybernate` and `sleep` are accepted as aliases,
and `wake` as an alias of `wakeup` (Proposed).

### 6.3 Local API

gRPC (`tonic`) over a Unix socket (Linux, macOS) or named pipe (Windows); **Implemented** (phase 10,
`crates/api`, protocol `proto/scribe/v1/api.proto`; `[api] socket` and `admin_group` in the config). Its calls follow the CLI and the UI mock data in `ui/tests/mocks/api-scenarios/`:
status, list hosts (paged, filtered), list / stream alerts, acknowledge alert, set mode, get / edit baseline, export, and the daemon controls `Health`, `Reset` (targets: counters, caches, config), `Hibernate` (optional duration) and `Wakeup`. `Health` is also served through the standard gRPC health protocol (`grpc.health.v1`, `tonic-health`) so generic tools can probe it. Module calls (Proposed, section 7.4.5): `ListModules` and `ModuleStatus` in the core service; each module may bring its own service in `proto/scribe/v1/modules/<id>.proto`, served only when the module is enabled. The API reports `api_version` so the UI can detect a mismatch.

Access (Proposed, extends NFR-9): the daemon checks the caller's identity from the socket (`SO_PEERCRED` on Linux, `getpeereid` on macOS, the named-pipe client token on Windows). Read calls (status, health, hosts, alerts, export) are allowed to everyone who may open the socket (root / Administrators and the `scribe` group); control calls (`Reset`, `Hibernate`, `Wakeup`, set mode, acknowledge, baseline edits) only to root / Administrators and the `scribe-admin` group (group names Proposed). Every control call is logged with the caller, the call and the result, and stored as an `audit` event; refused calls too. The identity comes from the OS once per connection and is attached to the request; identity fields inside messages are ignored. Transport hardening (socket in a `root:scribe` `0750` directory, named-pipe access list with `first_pipe_instance` and `reject_remote_clients`, clients checking the server, message size, timeout and stream limits, `export` streamed and written by the CLI as the caller) is in section 12.1.1. There is no TCP listener.

### 6.4 Desktop UI

Tauri app talking only to the local API; **Planned** (not in the 14 phases). Test folders and mock API data exist.

### 6.5 macOS Network Extension

`ScribeExtension`, a Swift System Extension (`NEFilterDataProvider`) started by macOS after user or MDM approval. Sends flow messages to `scribed` over XPC (draft format in `testdata/events/macos-ne/`). **Planned.**

### 6.6 Development and release entry points (implemented)

| Entry point | Purpose |
|---|---|
| `cargo run -p scribe-test-support --bin gen-fixtures [-- --check]` | Regenerate or check pcap fixtures and fuzz seeds |
| `scripts/version.sh` | Show, compute, set and check versions: highest tag by SemVer, sync report (`versions`), next version after the highest known, changelog release section; tested by `scripts/test-version.sh` |
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
| Enrichment | `crates/enrich` | DNS cache, SNI / HTTP `Host` / DNS / QUIC parsing, security classification; full HTTP request and URL parsing moves to the URL module | core | Partly (TLS detection, DNS cache) |
| Module API | `crates/module-api` (`scribe-module-api`) | `Module`, `FlowHook`, `Source`, `Manifest`, `ModuleContext`, notes, records, metric samples | core | Implemented |
| URL module | `crates/module-url` (`scribe-module-url`, feature `url`, default on) | Plaintext HTTP request parsing, URL privacy, request counters, `scribe url` commands | module-api | Partly (module, config, hook, conformance, request parser and URL privacy; `scribe url` in phase 10) |
| Kernel metrics module | `crates/module-kperf` (`scribe-module-kperf`, feature `kperf`) | Example of a later module: TCP retransmits, RTT, run-queue delay from kernel probes | module-api, sensors' `ProbeHost` | Idea (not planned) |
| Linux sensor | `crates/sensor-linux` | eBPF probes with `aya`, process lookup | core | Stub |
| Windows sensor | `crates/sensor-windows` | ETW kernel-network and DNS-client events, Npcap for payloads | core | Stub |
| pcap sensor | `crates/sensor-pcap` | Capture on every OS (macOS today, the fallback on Linux and Windows), no process info; libpcap / Npcap loaded at run time | core | Implemented (phase 6) |
| macOS extension | `macos/ScribeExtension` | Network Extension + XPC bridge | — | Planned |
| Storage API | `crates/storage-api` | `StateStore`, `EventSink`, `StorageFactory`, data model, errors | core | Implemented (interfaces) |
| Storage manager | `crates/storage-manager` | Backend registry, routing to sinks; later host cache, batching, spool, retention | storage-api, backends | Implemented (registry, writer tasks, spool, outage buffer, host cache, health)
| SQLite backend | `crates/storage-sqlite` | Default state store and event sink | storage-api | Implemented (schemas v1–v2, both conformance suites)
| PostgreSQL backend | `crates/storage-postgres` | Optional state store and event sink | storage-api | Stub (schema v1 done) |
| Policy engine | `crates/policy` (`scribe-policy`), no I/O | Modes, scoring rules, threat lists, dedupe, learn time limit | core | Implemented (phase 4) |
| Alert outputs | `crates/alerts` (`scribe-alerts`) | Dispatcher (queue and rate limit per output), log, webhook; OS notifications come from the `scribe notify` agent in the user's session | core | Partly (dispatcher and log, phase 11 step 1) |
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

**Decision:** option A. It keeps the policy engine free of I/O, so the scenarios can drive it directly with the test doubles, and the CLI and UI link only the API client. Options B–D are kept for the record.

### 7.3 Test and support modules (implemented)

| Module | Location | Responsibility |
|---|---|---|
| Test support | `crates/test-support` | `FakeSensor`, `FakeClock`, `MemoryStore`, `MemorySink`, `FaultySink`, `RecordingAlertSink`, packet builders, pcap writer, `gen-fixtures` |
| Storage conformance | `crates/storage-conformance` | Contract tests for every storage backend |
| Sensor conformance | `crates/sensor-conformance` | Contract tests for every sensor, plus the local traffic generator |
| Test data | `testdata/` | pcap fixtures, scenarios, raw sensor records, schema snapshots |
| Fuzzing | `fuzz/` | cargo-fuzz targets and seeds |
| End-to-end | `tests/e2e/` | Install, mode, upgrade, uninstall scripts per OS |
| Module conformance | `crates/module-conformance` | Contract tests for every module (section 7.4.7) |

### 7.4 Module framework (implemented in phase 0b)

Goal: new functionality (kernel performance metrics, and things not planned yet) arrives as a module
without editing `core`, `storage-api`, the schemas, the config model or the API. URL tracking is the
first module and the model for later ones. Before phase 0b it was spread through the core (`FlowEvent.url`,
`FlowKind::Request`, `Host.req_count`, `enrich/http.rs`, `privacy.url_query`); phase 0b took it out.
What was built differs from the first draft in the points listed in 7.4.9.

#### 7.4.1 Packaging

- Modules are **compiled in** and chosen by Cargo feature, like the storage backends: `url` (default on), `kperf` later. A `ModuleRegistry` in `scribed` works like the storage `Registry`.
- No dynamic loading (`dlopen`): Rust has no stable plugin ABI, and loaded libraries would bypass release signing (NFR-19). WebAssembly or out-of-process modules over gRPC can be added later behind the same trait, if third parties ever need it.

#### 7.4.2 Interface (`scribe-module-api`)

```rust
pub trait Module: Send + Sync {
    fn manifest(&self) -> &Manifest;  // id, version, config section, record kinds, metrics,
                                      // API service, access class per call, needs (payload, privileges)
    fn configure(&mut self, doc: &ConfigDoc<'_>) -> Result<Reload, ModuleError>; // reads [modules.<id>]
    fn start(&mut self, ctx: ModuleContext) -> Result<(), ModuleError>; // Clock, Emitter, stored state
    fn pause(&mut self);              // hibernate
    fn resume(&mut self);             // wakeup
    fn stop(&mut self);               // `start` may follow again
    fn health(&self) -> ModuleHealth;
    fn effective_config(&self) -> Option<toml::Table> { None } // for --check-config
    fn flow_hook(&self) -> Option<&dyn FlowHook> { None }    // sees flows (url)
    fn source(&mut self) -> Option<&mut dyn Source> { None } // produces its own data (kperf)
}
```

- **Flow hook:** called for each flow with its context and first payload bytes; returns flow notes and optional policy signals. It must be fast; slow modules get flows through a bounded queue instead.
- **Source:** runs on its own schedule or from a kernel feed and emits records or metric samples.
- Time comes only from `ModuleContext`'s `Clock`.

#### 7.4.3 Outputs: the only ways a module produces data

| Output | Use | Change to core / storage |
|---|---|---|
| **Flow notes** | Data attached to a flow (URL, HTTP method) | `FlowEvent.url` and `FlowKind::Request` are replaced by `notes: Notes`, a small map of module id → typed value, stored as JSON; core no longer knows HTTP |
| **Module records** | A module's own events (`url.request`) | `StoredEvent::Module { module, kind, schema, payload }`; sinks subscribe by name: `events = ["flow", "url.request", "kperf.sample"]` |
| **Metric samples** | Time series (kernel retransmits, RTT, run-queue delay) | Built-in `MetricSample { name, labels, value, ts }` and a `metrics` table usable by any module |
| **Module state** | A module's own totals and settings | Per-module key–value area in the state store (`module_state`) |

- Host counters keep only what every flow has (connections, bytes). `req_count` becomes the URL module's request total.
- **Policy signals:** a hook may return `Signal { reason, detail }` with a namespaced reason (e.g. `url.credentials_in_query`); the score comes from `[policy.scores]`, so the policy engine stays free of I/O and module-agnostic.
- **Alerts:** an alert carries the flow's notes, so the `plaintext` alert still shows the URL when the URL module is on.

#### 7.4.4 Sensors and enrichment

- Sensors capture; modules parse. Sensors hand the first N payload bytes of each flow to the pipeline. Core enrichment keeps what every flow needs: SNI, the HTTP `Host` header for the host name (FR-3), DNS and security classification.
- Payload past the ClientHello / `Host` header is copied only when an enabled module declares `needs: payload`. With the URL module off, no HTTP request bytes are kept (privacy gain).
- **`ProbeHost`:** modules never load eBPF programs or start ETW sessions themselves. The Linux and Windows sensors offer a probe host that loads module-supplied probes inside the privileged part before privileges are dropped (section 12.1.1); the module reads the maps unprivileged. The module manifest declares the privileges it needs (`CAP_BPF`, `CAP_PERFMON`, an ETW provider).

#### 7.4.5 Config, API and CLI

- `[modules] enabled = ["url"]` and one `[modules.<id>]` section per module, checked by the module itself. It receives the section as `Spanned<toml::Value>`, so errors keep their line and column; `configure` reports live or needs-restart for `reset --config` (section 8.5.2).
- `privacy.url_query` moves to `[modules.url] query` (section 12.2); the old key stays as a deprecated alias for one version.
- API: `ListModules` and `GetModule` in the core service; per-module services in `proto/scribe/v1/modules/<id>.proto`, built by the module crate and served only while the module is enabled; a module reads its stored records through `RecordReader` (implemented in phase 10).
- CLI: `scribe modules`; each module crate may add a `clap` subcommand behind its `client` feature (`scribe url …`). `scribe daemon status` gets a per-module section with health, counters and drops.

#### 7.4.6 URL module (`crates/module-url`)

- Flow hook on plaintext TCP flows: parses the HTTP/1.x request line and headers, builds the URL, applies `query` (`redact_values` default, section 12.2), always strips user info.
- Outputs: note `url` on the flow, record `url.request`, request counter per host in module state.
- CLI `scribe url list [--host] [--since]`; API service `scribe.v1.modules.url`.
- Tests: fixture `http_plain`, the URL privacy table in section 12.2, fuzzed request parser.

#### 7.4.7 Safety and testing

- Each module API call declares read or control; the daemon enforces the read / control split (section 6.3) and refuses undeclared calls. Control calls are audited.
- NFR-20: per-flow time budget, bounded queues with counted drops, a panic disables only that module (health degraded). Modules run unprivileged.
- `scribe-module-conformance` checks: start, stop and start again; pause and resume; config errors with line numbers; reload live vs restart; hook time budget; no panic on fuzzed payloads; versioned record schemas; refusal of undeclared calls.

#### 7.4.8 Example of a later module: kernel metrics (`kperf`)

Not planned yet; shows the framework covers it. A `Source` module emitting metric samples:
Linux via eBPF through `ProbeHost` (`tcp_retransmit_skb`, RTT from sockops, run-queue latency),
Windows via ETW and performance counters, macOS a smaller set via `sysctl` / `nstat`.
`scribe metrics show <name>`; samples go to sinks subscribed to `kperf.sample`. Rough size 8–12 days.

#### 7.4.9 What phase 0b changed from the first draft

1. **`FlowKind::Request` became `Payload`** (more client bytes seen on an existing flow), instead of
   leaving core entirely: a sensor still has to report the second HTTP request on a kept-alive
   connection. The URL module turns those bytes into the `url` note and the `url.request` record.
2. **Notes, `ModuleRecord` and `MetricSample` live in `scribe-core`**, not in `scribe-module-api`, so
   the storage crates don't depend on the module API.
3. **Sensors send `Observation`s now** (event plus up to `HEAD_MAX` = 4 KiB of client bytes), not from
   phase 6: the sensors were stubs, and the module suite needs observations with bytes.
4. **The URL module started as a skeleton** (manifest, config, hook, request counters, conformance); the
   request parser (`parse::request_url`) and the `query` rules followed in phase 3.
5. **Module kinds are `Cow<'static, str>`**: static names from manifests, owned names when records are
   read back from storage. `EventKind` is `Clone`, not `Copy`.

Also: `configure` takes a `ConfigDoc` (the whole file; `section::<T>(id)` keeps error lines exact, `get`
reads keys elsewhere), the URL module itself honours the deprecated `privacy.url_query`, and
`effective_config` lets `--check-config` print each module's settings.

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
- **Rules settled in phase 4** (`scribe-policy`):
  - Signals are scored for **unlisted** hosts only; a listed host never gets a score alert.
  - `raw_ip` means the flow has no host name at all (no SNI, `Host`, sensor name or DNS answer). An ECH outer name counts as a name.
  - Caution: a score alert (top signal) wins over `plaintext`; `plaintext` is used when the score stays below the threshold. Alert mode: `unlisted_host` wins over `plaintext`.
  - Ties between signals keep this order: `raw_ip`, `unusual_port`, `high_entropy`, `new_tld`, `new_process`, `threat_list`, then module signals.
  - The TLDs of baseline hosts count as seen; every judged flow adds its TLD and process to what has been seen, in every mode.
  - The dedupe window counts from the **last alert**, not the last flow. A repeat inside the window that brings new notes (the URL of a later request) adds them to the earlier alert.
  - Module signals score `[policy.scores] "<module>.<reason>"` (0–100, the module must be enabled); a signal with no score counts 0.
  - Threat lists: a domain also covers its subdomains; `ips` takes addresses and CIDR networks; lines that can't be read are skipped and counted. A list file that can't be read stops `scribed`; `url` lists are downloaded from phase 11 on.
- **Check against the scenarios:** an ordinary new host scores 25 (`new_process`) and stays quiet; the raw-IP case scores 60 + 30 + 25 and alerts as `raw_ip`; the random-looking domain scores 50 + 20 + 25 and alerts as `high_entropy`. This matches `caution-ordinary-new-host`, `caution-raw-ip`, `caution-high-entropy-domain` and `learn-auto-switch`.

### 8.4 Degraded operation

| Situation | Behaviour | Status |
|---|---|---|
| Native sensor unavailable (old kernel, extension not approved) | Fall back to the pcap sensor (`FallbackSensor`); status reports no process info. Without libpcap / Npcap either, `scribed` logs it and keeps running without a sensor | Implemented (phase 6) |
| Event sink down | Spool to disk (`storage.spool`), replay in order; when `max_size` or `min_free_disk` is reached drop the oldest and count drops | Implemented (phase 2) |
| State store unavailable | Keep the latest events in an in-memory buffer (`storage.buffer`); when full, drop the oldest to add the newest; count drops, report unhealthy, replay in order on recovery (FR-25) | Implemented (phase 2) |
| Hostname hidden (ECH, DoH) | Track by IP or outer name, flag it | Implemented (phase 5) |
| Invalid config | At start: refuse to start, report the error and line (Implemented). On reload: keep the running config, report the error and line (Planned) | Partly |

### 8.4.1 pcap sensor (implemented in phase 6)

| Item | Behaviour |
|---|---|
| Library | libpcap (`libpcap.A.dylib`, `libpcap.so.1`) or Npcap (`System32\\Npcap\\wpcap.dll`), loaded at run time; `SCRIBE_LIBPCAP` names another file. Missing library or no permission: the sensor reports why and `scribed` runs without capture |
| Device | `[sensor] interface`; `""` = Linux `any`, else the first device that is up, not loopback, with an address. Filter `tcp or udp`, no promiscuous mode, non-blocking reads |
| Direction | A TCP flow starts at the client's SYN; a UDP flow at the first datagram from an address of this machine (all devices' addresses). Connections open before capture started are not tracked |
| First bytes | Reassembled by sequence number up to 4 KiB: a whole ClientHello, an HTTP head to the empty line, or the first segment; reported 1 s after the SYN with what arrived otherwise |
| Later bytes | Plaintext HTTP requests as `Payload` when an enabled module needs payload (`Sensor::set_payload`); the next QUIC long-header datagrams as `Payload`; DNS answers (UDP from port 53) as `DnsResponse`; all other client bytes counted and reported by `Close` (FIN, RST, 5 min TCP / 60 s UDP idle, a full table of 65,536 flows) |
| Time | From the packets, so a replay (`flows::replay`) behaves like live capture |

### 8.5 Daemon run states (implemented in the daemon in phase 5; commands in phase 10)

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
  raise no alerts. Every module is paused, sources included (FR-35).
- **Visible gap:** entering and leaving hibernation writes a log entry and an `audit` event
  (`hibernate` / `wakeup` with the caller and the planned end) to the event sinks subscribed to it, so stored history shows
  the gap. `status` and `health` show `hibernating since … until …`.
- **Timers:** the `learn_for` countdown pauses while hibernating, so learn mode isn't cut short by a pause.
  The alert dedupe window keeps running on the clock.
- **Mode changes and baseline edits** are accepted while hibernating and apply after wakeup.
- **Limits and alerting:** hibernation always has an end (`--for`, capped by `daemon.max_hibernate`),
  and starting it raises a `hibernated` alert, so silencing scribe is never quiet (section 12.1.1).
- **Implementation:** `Pipeline::hibernate` / `wakeup` / `tick`; `serve_controlled` takes `Command`s (`Hibernate`,
  `Wakeup`, `Reset`, `Status`) and stops or starts the sensor when the state changes. Observations that still
  arrive while hibernating are dropped and counted (`dropped_hibernating`); held QUIC flows are judged before
  the pause. A second `hibernate` sets a new end (still capped) with an audit event and no new alert. The
  `hibernated` alert has no host and the destination `0.0.0.0:0`; its `daemon` note carries the caller and the
  planned end. At start `scribed` restores the stored alert state (`StateStore::alert_states`): acknowledged
  keys stay silent, and keys alerted inside the dedupe window aren't alerted again (phase 10).
- **Restart:** hibernation doesn't survive a restart; `scribed` always starts in `running` (Proposed;
  the alternative of persisting it in the state store is open question 9).
- **Stops and crashes:** a daemon stop, a crash found at the next start, and gaps in the audit sequence are
  stored as `audit` events; the remote sink sees missing heartbeats (NFR-18).

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
| `mode` (only when the file's value changed, so a mode set through the API isn't undone), `profile` (its baseline is loaded), all of `[policy]` (scores, threshold, usual ports, entropy; threat list files read again), `[modules.*]` and `privacy.url_query`, `[daemon]`, `[log] level` (unless `SCRIBE_LOG` is set); `[alerts]` | `data_dir`; the state store backend and its URL; any `[[storage.sinks]]` change, retention and batching included; cache, buffer and spool limits; `[log] file`, `output`, `format`, `rotate`, `max_size`, `keep`; the sensor; the API socket |

A reload is all-or-nothing for the live settings: if the file fails any check, or a threat list or the new
profile's baseline can't be read, nothing changes and the running config stays. Restart-only changes are
reported on every reload until `scribed` restarts. Each reload writes an `audit` event naming the caller and
both lists. Implemented in phase 5 (`config::reload`, `Command::Reload`, SIGHUP); sink, limit and log-format
changes may become live later.

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
| `[policy.scores] "<module>.<reason>"` | 0–100, module enabled | none (unscored module signals count 0) | Implemented |
| `[policy.usual_ports] tcp`, `udp` | port lists | section 8.3 | Draft default |
| `[policy.entropy] min_label_length`, `min_bits_per_char` | integer, number | `10`, `3.5` | Draft default |
| `[[policy.threat_lists]] name`, `path` or `url`, `format`, `refresh` | — | none | Draft default |
| `[modules] enabled` | list of compiled-in module ids | `["url"]` | Implemented (section 7.4) |
| `[modules.url] query` | `full` \| `redact_values` \| `strip` \| `path_only` \| `hash` | `redact_values` | Implemented (section 12.2) |
| `[modules.url] hash_key` | secret reference for the `hash` key | `file:<data_dir>/url_hash.key` (created on first start) | Implemented |
| `[privacy] url_query` | as `[modules.url] query` | — | Deprecated alias, read with a warning for one minor version |
| `[alerts] log` | boolean: a `scribe::alert` warning per alert in scribed's log | `true` | Implemented (phase 11) |
| `[alerts] max_per_minute` | integer, per output; the rest counted and reported once a minute; `0` = unlimited | `30` | Implemented (phase 11) |
| `[[alerts.webhooks]] name`, `url`, `secret`, `pin_sha256`, `timeout` | unique name (not `log`); `https://` (`http://` only to loopback); secret reference; optional pin; `1s`–`60s` | none; timeout `10s` | Implemented (phase 11) |
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
| `[[storage.sinks]] events` | list of `flow`, `alert`, `audit`, `metric` and record kinds of enabled modules (e.g. `url.request`); `[]` = all | `[]` | Decided |
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

#### 9.1.1 Proposed config keys (security design; not in config v1 yet)

These keys come from section 12.1.1 (the module keys landed in phase 0b and are in the table above). They are **Proposed** and are **not** accepted by the v1 config yet
(unknown keys are rejected); each lands with the phase that implements it, together with
`config/scribe.toml`, the skill and the config tests.

| Key | Values / default | Phase |
|---|---|---|
| `daemon.max_hibernate` | duration, default `4h`, `""` = unlimited (warned at every start); the cap for `scribe daemon hibernate` | Implemented (phase 5) |
| `sslmode` in `[storage.state]` and `[[storage.sinks]]` (Postgres) | `verify-full` (default), `verify-ca`, `require`; `disable` and `prefer` only for loopback hosts | 12 |
| `ca`, `client_cert`, `client_key` in the same tables | CA file path; TLS client certificate and key, the key as a credential reference (`keychain:` …) | 12 |
| `[[alerts.webhooks]]` `secret` | credential reference for the `X-Scribe-Signature` HMAC key | Implemented (phase 11) |
| `[[alerts.webhooks]]` `pin_sha256` | optional certificate pin (hex SHA-256 of the leaf certificate's DER) | Implemented (phase 11) |
| `[[policy.threat_lists]]` `sha256` / `minisign_key` | optional integrity check of a downloaded list | 11 |
| `[[policy.threat_lists]]` `max_entries` | entry cap per list | 11 |
| `storage.encrypt` | `false` (default); `true` = SQLCipher database and AES-256-GCM spool, key in the OS secret store | 13 |

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
| `ech` | The ClientHello used ECH: `hostname` is only the outer public name; `unresolved()` is true for these and for flows with no name |
| `notes` | Values from modules, keyed by module id; the URL module writes `notes.url` (replaced `url` in phase 0b) |
| `security` | `tls`, `quic`, `plaintext` or `unknown` |
| `bytes_out` | Bytes sent |
| `kind` | `new_flow`, `payload` (more client bytes on an existing flow; was `request`) or `close` |

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

### 10.3 Schema v2 for modules (implemented in phase 0b)

Released snapshots are never edited, so module support is a new schema version: migration `0002_modules.sql` for both backends, snapshots `testdata/db/sqlite/v2.db` and `postgres/v2_seed.sql` from `seed_v2.sql` (`testdata/db/build.sh`). The SQLite backend (phase 1) is built against v2 directly. Rows with `schema_version` 1 keep their payload layout (flows with `url`); readers convert them.

| Change | Content |
|---|---|
| `events` | adds `module` (null for core kinds) and `kind` as text (`flow`, `alert`, `audit`, `url.request`, …) |
| `metrics` (new) | name, labels (JSON), value, timestamp; retention per sink like events |
| `module_state` (new) | module id, key, JSON value, updated at |
| `hosts.req_count` | kept for v1 compatibility, written from the URL module's state; dropped in a later version |

### 10.3.1 Schema v3 for per-process counters (implemented in phase 5)

Migration `0003_processes.sql` for both backends, snapshots `testdata/db/sqlite/v3.db` and `postgres/v3_seed.sql`
(from `seed_v3.sql`):

- `hosts.unresolved`: on when the host is an IP or only an ECH outer name was seen; only turns on. The migration
  sets it for IP hosts already stored.
- `process_hosts (process, host)` with first / last seen, connections, requests and bytes (FR-9). `HostDelta`
  gains `unresolved` and `process`; one upsert updates both tables in one transaction, and a delta without a
  process counts for the host only. `StateStore::process_hosts(process)` lists them.
- Alert rows also keep `dst_port` and the flow's `notes` (payload keys; older rows read as 0 and empty).
- Hourly buckets (FR-9) arrive with schema v4 (section 10.3.2).

### 10.3.2 Schema v4 for hourly counters (implemented in phase 10)

Migration `0004_hours.sql` for both backends, snapshots `testdata/db/sqlite/v4.db` and `postgres/v4_seed.sql`
(from `seed_v4.sql`): `host_hours (host, hour)` with connections, requests and bytes per host per hour (the
hour's start). Every host upsert with a non-zero delta adds to the bucket of its `seen_at` hour in the same
transaction. `StateStore::host_hours(host, since)` reads them (API `ListHostHours`, `scribe hosts --hourly`);
`prune_host_hours(before)` deletes old ones, which `scribed` does at start and every hour for buckets older
than `[storage.hours] keep` (default `90d`, `""` = forever). Host totals are never pruned.

### 10.4 SQLite backend (implemented in phase 1)

| Item | Value |
|---|---|
| Library | `rusqlite` 0.43 with bundled SQLite (needs Rust 1.89, the current minimum) |
| Connection | Opened on first use; WAL, `synchronous = NORMAL`, `busy_timeout` 5 s; calls are short and serialized per backend instance |
| Migrations | Missing ones applied in order, each in its own transaction, recorded in `schema_migrations` and `user_version`; a database with a newer schema than the build is refused (`StorageError::Data`) |
| Health | `Ok` at the latest schema, `Degraded` while a migration is pending, `Down` when the file can't be opened |
| Hosts | One upsert per delta, in a transaction: counters added, `first_seen` / `last_seen` as min / max, `tls_seen` / `plaintext_seen` / `unresolved` only turn on; the process + host row too when the delta names a process |
| Lists | Hosts sorted by name, filter matched literally (`%` and `_` escaped); baselines sorted by host, re-adding keeps the first entry; IP expiries only extend |
| Events | A batch is one transaction; flow, alert, audit and module records in `events`, metric samples in `metrics`; payload layout from `scribe_storage_api::codec` |
| Queries | Both tables merged oldest first (then events before metrics, then insertion order); `since` inclusive, `until` exclusive; `total` counts all matches |
| Old rows | Schema 1 flows (`url`, `request`) are read as `notes.url` and `payload` |
| Files | `state.db` and `events.db` in `data_dir` by default; state and sink may share one file |

### 10.5 Storage manager (implemented in phase 2)

| Item | Value |
|---|---|
| Lifecycle | `StorageManager::from_config` builds the backends; `start(RunOptions)` returns a running `Storage` on the Tokio runtime; `shutdown` writes what is queued, gives buffered state writes a last replay and flushes every sink |
| Writer tasks | One per sink. `publish` never waits: events go to each subscribed sink's queue (1,024 messages); a full queue drops that sink's share and counts it (NFR-7). Batches are written at `batch_max_events` (capped by the sink's `max_batch`) or after `batch_max_wait` |
| Spool | `<spool dir>/<sink>/<seq>.jsonl`, one stored row per line, 4 MiB segments. A failed batch and every later one go to the spool, so order holds; replay oldest first with back-off 1 s doubling to 60 s; at-least-once. All spools share `max_size` and `min_free_disk`; at a limit the sink's oldest segments are dropped (counted), or the new batch if nothing older is left. Replayed at start after a restart |
| Retention | Hourly `EventSink::delete_before(now − retention)` for sinks without native retention |
| State outage buffer | Backend or config errors start buffering; that write and all later ones wait in order within `storage.buffer` (oldest dropped, counted); replay with back-off. Buffered `upsert_host` returns id 0; a following `link_ip(0, …)` is linked by name on replay. `Data` errors go back to the caller, or are dropped on replay |
| Host cache | LRU of hosts within `storage.cache` (`max_hosts`, `max_memory`), plus each profile's baseline; writes update cached entries; `clear_cache` for `reset --caches` |
| Health | `Storage::health`: the state store (degraded while buffering), each sink (degraded while spooling or after drops) and the worst of them; `sink_status`, `state_status`, `cache_status` give the counters for `scribe daemon status` |
| Time | Batching and retry waits use the runtime's monotonic clock (tested with paused Tokio time); retention cutoffs use `Clock` |

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

#### 12.1.1 Security design per interaction (Proposed)

Principle: locally, who is calling matters more than encryption (the peer identity comes from the OS);
everything that leaves the host uses TLS plus authentication. All crypto uses `ring`, and TLS uses
`rustls` with the `ring` provider, so there is no OpenSSL dependency.

**Local API (CLI / UI ↔ daemon, section 6.3, phases 5 and 10)**

- Unix socket inside a `root:scribe` directory with mode `0750` (e.g. `/run/scribe/api.sock`); the socket file's own mode is not relied on, because BSD-derived systems have ignored it.
- Windows named pipe: explicit access list (SYSTEM, Administrators, `scribe`, `scribe-admin`), `first_pipe_instance(true)` against pipe-name squatting, `reject_remote_clients(true)`.
- Caller identity read once per connection from the OS (`peer_cred()`, pipe client token) and attached to tonic request extensions; identity claims inside messages are ignored.
- Clients check the server: the CLI and UI require the socket to be owned by root, or the pipe server process (`GetNamedPipeServerProcessId`) to run as SYSTEM, before sending anything; this stops a fake `scribed`.
- Limits: gRPC message size, per-call timeouts and a cap on concurrent streams (e.g. `status --watch`).
- `export`: the daemon streams records; the CLI writes the file as the calling user. The daemon never writes to a client-supplied path.
- Silencing controls (`hibernate`, mode, `reset`): admin only, audited, maximum `--for` duration (no open-ended hibernation by default), an alert when hibernation starts.
- UI (Tauri): read-only by default; control calls ask for elevation (polkit, Authorization Services, UAC) instead of permanent `scribe-admin` membership; strict content security policy, no remote content, only the IPC commands it needs.

**macOS Network Extension ↔ daemon (XPC, section 6.5)**

- launchd Mach service; code-signing requirement checked in both directions (Team ID + bundle ID, `setCodeSigningRequirement` or the audit token with `SecCode`).
- Messages are untrusted bytes: versioned schema, size limits, decoder fuzzed with the other parsers.

**Sensors and privileges (NFR-8)**

- Privilege split: loading eBPF, the ETW kernel session and opening pcap stay in the small privileged part; the parsers (SNI, QUIC, HTTP, DNS) run after privileges are dropped.
- Linux: pinned bpffs maps root-only; keep only `CAP_BPF` / `CAP_PERFMON` as needed, drop the rest after attaching.
- systemd unit: `NoNewPrivileges`, `ProtectSystem=strict` with `ReadWritePaths` for data and logs, `PrivateTmp`, `CapabilityBoundingSet`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute`.
- Windows: service SID; processing under `NT SERVICE\scribed` instead of SYSTEM where the ETW session allows it.

**Postgres sink (leaves the host)**

- TLS on by default via `tokio-postgres-rustls`; the config check rejects `sslmode=disable` / `prefer` for any non-loopback host; default `verify-full`, optional `ca` path.
- TLS client certificates as an alternative to passwords; the key referenced like `credentials` (`keychain:` and the others).
- Least-privilege role: the sink account has `INSERT` only on the event tables (no `SELECT` / `UPDATE` / `DELETE`); one role per host with row-level security on `host_id`, so a compromised host can't forge or erase another host's history.
- scribed tags its own connections so its sink traffic doesn't alert; a plaintext connection from scribed itself still alerts.

**Webhook alerts and threat lists**

- HTTPS only (`http://` only to loopback); optional certificate pinning; no redirects to other hosts; timeouts and size limits.
- Webhook requests signed with HMAC-SHA256 in `X-Scribe-Signature: t=<ts>,v1=<mac>`, the MAC over `<ts>.<body>`; the timestamp lets receivers reject replays; the secret comes from a keychain reference, never the URL; the payload follows `privacy.url_query`. Implemented in phase 11: JSON `{type: "alert", version: 1, machine, scribe_version, sent_ms, ts_ms, reason, score, host, dst, process_path, notes}` (`type: "suppressed"` with `count` for a rate-limit summary); any 2xx is success; 3 attempts (waits 1 s, 4 s) on network errors, 429 and 5xx only; a secret that can't be read refuses the start or reload.
- Threat lists: optional integrity check per list (pinned `sha256` or a `minisign` public key); a failed refresh keeps the last good list; maximum entry count.

**Data at rest**

- Default: strict file modes plus full-disk encryption. Database, spool, logs and exports are created `0600` or `0640 root:scribe-admin`.
- Like sshd's StrictModes, scribed refuses to start if the config, `data_dir` or a `file:` credential is writable by group or others. Implemented in phase 5 for the config file and `data_dir` (`security::strict_modes`, Unix); `file:` credentials are checked by `scribe-secrets`; Windows ACLs by the installer (phase 13).
- Optional `storage.encrypt = true`: SQLCipher (`rusqlite` feature `bundled-sqlcipher`) and AES-256-GCM spool records (`ring`), key in the keychain / DPAPI / Secret Service (TPM-sealed where available). The daemon must open the key unattended at boot, so this protects stolen disks and backups, not a live root attacker.
- The per-install HMAC key for `[modules.url] query = "hash"` is a secret reference: by default a root-only `file:` in `data_dir` (`url_hash.key`, `0600`), or `hash_key` pointing at the OS store once its backends land (phase 11).

**Tamper evidence (NFR-18)**

- Audit and alert records carry a sequence number and `prev_hmac`, so deleted or edited rows show up locally and in the sink. Implemented in phase 5 (`scribe_daemon::chain`): HMAC-SHA256 over the sequence, the previous HMAC and `codec::chain_bytes` (kind, host, time and payload as sorted compact JSON); key `audit.key` in `data_dir` (created on first start, mode 600), state `audit.chain`; `chain::verify` reports gaps, mismatches and unlinked records.
- Each host writes a heartbeat to the remote sink; the central side alerts on gaps.
- Daemon stops, crashes and sequence gaps are stored as `audit` events. Implemented in phase 5 for starts, clean stops and unclean stops (a `scribed.running` marker left in `data_dir`); gap checks run in `scribe audit verify` (phase 10).

**Remote / fleet API**

- No TCP listener; the central Postgres sink gives the fleet view, and SSH-forwarding the Unix socket works without new code.
- If ever required: off by default, loopback by default, TLS client certificates only (tonic `tls-ring`), the same read / control split and audit as the local API.

**Releases and supply chain (NFR-19)**

- `SHA256SUMS` signed (Sigstore cosign keyless with GitHub OIDC, or minisign); `actions/attest-build-provenance`; Authenticode (Windows), notarization (macOS), signed `.deb` / `.rpm` repositories.
- `cargo deny` and `cargo audit` in the Tests workflow.
- Actions pinned by commit SHA; minimal `permissions:` per job, most of all for Bump version, which pushes to `main`.

**Suggested order**

| When | What |
|---|---|
| Phases 5 / 10 (API, daemon commands) | Local API access checks and limits, StrictModes checks, hibernate limits |
| Postgres / alert phases | Postgres TLS on by default and sink role; HTTPS and signed webhooks |
| Native sensors | XPC code signing; privilege split and service hardening |
| Phase 13 (installers) | Release signing and attestations; optional encryption at rest |
| Any time | `cargo deny` / `cargo audit`; Actions pinned by SHA |

### 12.2 URL privacy (`privacy.url_query`)

**Decision:** default `redact_values` (FR-26). Since phase 0b the key is `[modules.url] query` (section 7.4.5); `privacy.url_query` is still read, with a warning. The values and behaviour below don't change.

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

The `hash` key is generated on first start (32 random bytes, stored as hex) in `data_dir/url_hash.key`, mode `0600`, owned by the service account; `[modules.url] hash_key` (a secret reference, section 9.1) names another store. The module does not start in `hash` mode when the key cannot be read or created. Without it, a hash of a short value such as a user id could be reversed by trying likely values.

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
| Parsing and enrichment (FR-3 – FR-8) | 14 pcap fixtures with expected flows (incl. a kept-alive connection), raw sensor samples, fuzz targets | Yes, except QUIC |
| Policy and modes (FR-11 – FR-15) | 19 daemon scenarios (incl. hibernation, reset, acknowledge, module signals) with `FakeSensor`, `MemoryStore`, `FakeClock` | Yes (runner in `tests/scenario`; 16 of 19 run, 3 need phase 5) |
| Storage (FR-9, FR-10, FR-17 – FR-19) | Storage conformance suite, schema snapshots, `FaultySink` | Yes |
| Capture (FR-1, FR-2) | Sensor conformance suite and traffic generator, draft raw records | Yes |
| API and UI (FR-20) | Mock API scenarios | Partly |
| Daemon controls (FR-27 – FR-31) | Daemon tests with `FakeSensor`, `FakeClock`, `FaultySink`; CLI tests against a daemon and against `MockApiServer`; mocks `daemon-down`, `daemon-restart`; sensor conformance case *stop, then start again* | Implemented (phase 10) |
| Modules (FR-32 – FR-35, NFR-20) | `scribe-module-conformance`; storage conformance cases for module records, metric samples and module state; URL module against `http_plain` and the 12.2 table; panic and slow-hook tests; schema v2 snapshot | Implemented (module and storage conformance, `ModuleHost` tests, v2 snapshot, `http_plain` / `http_keepalive` end to end, the 12.2 table) |
| Install and upgrade (UC-10) | End-to-end scripts | Yes (need installers) |
| Non-functional (NFR-1 – NFR-5) | Performance and soak runs | Planned |
| Security (NFR-8 – NFR-10, NFR-17 – NFR-19) | API tests calling every control endpoint as a read-only and an admin peer; fake-server test for the CLI's server check; oversized messages and too many streams; StrictModes file-mode table; `hibernate` cap and alert with `FakeClock`; Postgres `sslmode` config errors and a TLS-only Postgres in CI; signed webhook test vectors; threat-list checksum mismatch; audit chain with a deleted and an edited row; XPC decoder and API requests fuzzed; `cargo deny` / `cargo audit`; release signature and attestation checked in the Release smoke test | Planned |

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
| 9 | Should hibernation survive a restart of `scribed`? | **Open.** Proposed: no, a restart always resumes processing, so a forgotten pause can't silence monitoring for good; `--for` covers planned windows (section 8.5). Since hibernation is now always capped by `daemon.max_hibernate` and alerts at start, keeping it across a restart (until its planned end) is less risky than before |
| 10 | Names: `hibernate` / `wakeup` with aliases `hybernate`, `sleep`, `wake`; `scribe status` kept as short form of `scribe daemon status` | **Proposed** (section 6.2.1) |
| 11 | Default for `daemon.max_hibernate`, and whether admins may set it to unlimited | **Answered:** `4h`; `""` (unlimited) allowed but logged as a warning at every start (section 12.1.1) |
| 12 | Group names `scribe` (read) and `scribe-admin` (control); who creates them | **Proposed:** these names, created by the installers in phase 13 |
| 13 | Release signing: Sigstore cosign keyless or minisign | **Open** (section 12.1.1, NFR-19) |
| 14 | When to build the module framework | **Answered:** phase 0b, done before phase 1 (plan.md) |
| 15 | How long `privacy.url_query` stays as a deprecated alias | **Proposed:** one minor version, with a warning at start |
| 16 | Out-of-process or WebAssembly modules for third parties | **Open**, not needed for v1 (section 7.4.1) |

## 16. References

- [plan.md](plan.md) — phases, estimates, milestones, risks
- [diagram.md](diagram.md) — components, connection flow, mode decision, storage plugin classes
- [status.md](status.md) — completion and coverage per module
- [test-approach.md](test-approach.md) — test levels and tooling
- [scribe-conventions skill](../.claude/skills/scribe-conventions/SKILL.md) — decided values
- [readme.md](../readme.md) — overview, build, versioning, workflows
