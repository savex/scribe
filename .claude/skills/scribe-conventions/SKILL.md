---
name: scribe-conventions
description: Assumptions, decisions and config values for scribe — modes and alert rules, storage roles and schema conventions, config keys, enrichment (SNI, DNS, ECH, QUIC with ring), versioning and releases, CI workflows, test doubles and test-data rules, performance targets. Use when implementing or changing any scribe module, config, migration, workflow, fixture or test.
---

# scribe conventions

The decisions, assumptions and concrete values agreed so far, collected in one place.
Use it as the reference when implementing a module, writing tests or changing CI.

- **Decided** values are already in the code, config or workflows; change them there and here together.
- **Proposed** values come from the design discussion but no code uses them yet.
- **Draft default** values are the defaults in the v1 config draft [config/scribe.toml](../../../config/scribe.toml); tunable after testing.
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
| Time-limited learn mode | `policy.learn_for` (default `""` = no limit), then switch to `policy.then` (default `caution`) | Draft default |
| Alert dedupe key | host + process path | Decided (`AlertState.key`) |
| Alert dedupe window | `policy.dedupe_window = "10m"` | Draft default |
| Hosts with no hostname | Tracked by IP, flagged "unresolved", never dropped | Decided (scenarios) |

**"Non-ordinary" signals for caution mode** (draft defaults, `[policy.scores]`):

| Reason id | Signal | Score |
|---|---|---|
| `raw_ip` | Connection to an IP with no preceding DNS lookup | 60 |
| `unusual_port` | Port not in `policy.usual_ports` | 30 |
| `high_entropy` | Longest label ≥ 10 chars with Shannon entropy ≥ 3.5 bits/char | 50 |
| `new_tld` | Top-level domain not seen before | 20 |
| `new_process` | Process that never made network connections before | 25 |
| `threat_list` | Host or IP in a configured threat list | 100 |
| `unlisted_host` | Host not on the baseline (used by `alert` mode) | — |
| `plaintext` | Non-TLS flow (used by `caution` and `alert`) | — |

- Scores of matching signals are added and capped at 100; caution alerts at `policy.threshold = 50`; the alert names the highest-scoring signal; 0 disables a signal.
- Usual ports: TCP 22, 53, 80, 443, 465, 587, 853, 993, 995; UDP 53, 123, 443, 853, 5353.
- Threat lists: none by default (fetching is outgoing traffic); local file or URL + `refresh`, formats `domains`, `hosts`, `ips`.
- These values reproduce the caution scenarios in `testdata/scenarios/`; keep them in sync.
- Module signals: `[policy.scores] "<module>.<reason>" = 0–100`; the module must be enabled; unscored signals count 0.
- Engine rules (specs 8.3, Implemented): scores only for unlisted hosts; `raw_ip` = no host name at all; caution prefers the top signal over `plaintext`, alert mode `unlisted_host` over `plaintext`; ties keep the table order, then module signals; baseline TLDs count as seen; dedupe window counts from the last alert; a repeat with new notes updates the earlier alert; acknowledged = silent for that host + process.
- Threat lists: domains cover subdomains, `ips` takes CIDR, unreadable lines skipped and counted, an unreadable file stops `scribed`. Downloads (`url`, phase 11, `crates/daemon/src/threats.rs`): `scribe-net` GET (64 MiB, 30 s), checks `sha256` pin, `minisign_key` (signature at `<url>.minisig`, prehashed and legacy accepted) and `max_entries` (default 1,000,000, any list); last good copy `<data_dir>/threat-lists/<name>.txt` loaded at start and replaced only by a checked list; `Feeds` tasks refresh every `refresh` (24h default, ≥ 5m, first wait from the copy's age), retry after 15 min; the main loop merges lists (`ThreatSet::merge`); reload of `[policy]` reloads lists and restarts the downloads.
- Scenario runner: `tests/scenario` (`serde_yaml_ng`), `ModuleHost` + `Policy` + `MemoryStore`; scenarios needing run states or per-process counters are `#[ignore]`d until phase 5.

## 3. Language, toolchain and code conventions

| Item | Value | State |
|---|---|---|
| Core language | Rust (edition 2021) | Decided |
| Minimum Rust version | **1.89** (`rust-version` in `Cargo.toml`; the Tests workflow builds with exactly that version) | Decided |
| Minimum version policy | *Follow dependencies*: the minimum is what the dependencies need. Raise it only when a dependency requires it, in the same commit, and add a row to the history below. Prefer staying ≥ 2 releases behind stable. No crate is pinned to an old release just to avoid a raise | Decided |
| Development toolchain | current stable | Decided |
| macOS capture piece | pcap sensor with process attribution from `libproc` (`scribe-process`, plan option 9B, chosen 2026-11-25). A Swift System Extension (`NEFilterDataProvider`) over XPC stays a later option (9A), outside the plan's totals; `macos/ScribeExtension/` and the draft XPC format are kept for it | Decided |
| Windows capture | ETW from user mode first; WFP driver / WinDivert only for later blocking. Option 8A (2026-11-25): a real-time session through `windows-sys` (no `ferrisetw`: last release 2024, older `windows` crate) on Microsoft-Windows-Kernel-Network (events 12 / 28 TCP connect, 42 / 58 UDP send; user data parsed field by field, integers little-endian, addresses and ports network order) and Microsoft-Windows-DNS-Client (3008: name, type, status, results text). DNS answers become a `DnsResponse` with a DNS message (all addresses under the queried name, TTL 300 s, at most 128). With Npcap, packets through the pcap sensor's flow tracker joined by `scribe_process::join` (shared with the eBPF sensor; `Connection` reports, the hold per sensor); without, `EtwFlows` makes flows from the events (UDP once per pid, socket and destination until 30 s quiet). Process path from Microsoft-Windows-Kernel-Process (`{22FB2CD6-…}`, keyword 0x10, events 1 start / 2 stop / 15 rundown requested with `EVENT_CONTROL_CODE_CAPTURE_STATE` at start; `ImageName` found as the first NT path (`\Device\`, `\??\`, `\SystemRoot\`) after the pid, since the fixed fields before it grow by version (Windows 10+: sequence numbers, token elevation, mandatory-label SID); `\Device\HarddiskVolumeN` → drive via `QueryDosDeviceW`, `\SystemRoot` → `%SystemRoot%`; the number of paths known is logged 5 s after start; stopped processes kept 60 s, at most 65,536), `QueryFullProcessImageNameW` only as fallback. Service account (step 3, 2026-11-25): `NT SERVICE\scribed` (`sc.exe config obj=`, `sidtype unrestricted`), in Performance Log Users (by SID S-1-5-32-559; enough to start the session, not to enable the providers), `EventAccessControl` add-DACL `TRACELOG_GUID_ENABLE` (0x80) on the three providers and `TRACELOG_ACCESS_REALTIME` (0x400) on the session's fixed GUID `defafa1b-0503-415d-80b4-7255907e23fe` (`-Remove` strips the account's ACEs from `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Security`), RX on its folder, Modify on `data` / `logs` / `-Writable`; `-LocalSystem` opt-out; the pipe client accepts SYSTEM or that account's SID; the pipe server reads the client's token from its process, else through the pipe (`ImpersonateNamedPipeClient`, identification level, `OpenThreadToken` as self, then `RevertToSelf`, abort if that fails); CI step `scripts/ci/windows-service-check.ps1` (installed service, `curl.exe` by the runner's account gets its path). Session (step 2): real-time session `scribe-etw` (an old one left over is stopped and restarted), `FlushTimer` 1 s, 64 KiB buffers (4–64), providers enabled at level verbose, all keywords, with an event-id filter (Kernel-Network 12 / 28 / 42 / 58, DNS-Client 3008; without the filter where it's refused); the callback only copies id and user data to a channel, a worker parses and joins; packet observations wait up to 1.5 s (`HOLD`) for their event; `EtwSensor::new(interface)` starts an inner `PcapSensor` when Npcap loads, else ETW alone (logged); needs Administrator; lost events logged at stop. Conformance: `etw_sensor_conforms` without packets (`SuiteOptions.sees_payload` false, 5 s timeout); on hosted Windows runners the pcap test runs only when `wpcap.dll` exists | Decided; steps 1–2 implemented, conformance green on Windows (run `45722367989`); step 3 (service account) green on Windows (run `45730673139`) |
| Linux capture | eBPF programs in C (`src/bpf/scribe.bpf.c`, `clang -target bpf`, CO-RE: minimal kernel struct definitions with `preserve_access_index` instead of a checked-in `vmlinux.h`, UAPI types from the system's kernel headers) loaded with `libbpf-rs` 0.27 (`libbpf-cargo` skeleton in `build.rs`, its rustfmt pass skipped so toolchains without rustfmt build; vendored libbpf linked statically); `fentry/tcp_connect`, `fexit/udp_sendmsg`, `fexit/udpv6_sendmsg` (skipped with a warning if it can't load), so kernel 5.8+ on x86_64 and 6.0+ on arm64; pcap sensor with socket-table attribution on older kernels. Linux build machines need `clang`, `libelf-dev`, `zlib1g-dev` (plan option 7B, chosen 2026-11-25 over `aya`). Design (2026-11-25): **who** from kprobes on `tcp_connect` and `udp_sendmsg` / `udpv6_sendmsg` (`struct scribe_flow` v2 in `src/bpf/scribe.h`, 856 bytes, host-order integers, network-order addresses, mirrored by `record.rs`; a version byte refuses mismatches; v2 adds the executable path, walked in the kernel from `mm->exe_file` through dentries and mount points, at most 32 steps and 512 bytes (the tail kept, `path_truncated` set), in the process's own mount namespace; the write position is kept in the record so the verifier prunes the walk) through a ring buffer; **what** from a socket filter on an `AF_PACKET` socket feeding the pcap sensor's `FlowTracker` (no libpcap); `Owners` joins them by exact addresses, then local port + remote (unbound UDP reports `0.0.0.0`), `OWNER_TTL` 10 min since last use, at most 65,536, executable path from the record (`/proc/<pid>/exe` only when the record has none, once per 5 s per pid). libbpf vendored and static; libelf and zlib dynamic from the system (iproute2 needs them too). Pids are reported in scribed's own pid namespace (`bpf_get_ns_current_pid_tgid` with `/proc/self/ns/pid`; processes outside it get none), executable path from the kernel (decided 2026-11-25 over keeping `CAP_SYS_PTRACE` for `/proc`). Ring buffer 1 MiB (records built in a one-entry per-CPU `scratch` map, then copied with `bpf_ringbuf_output`: kernel 5.8's verifier loses a reserved ring-buffer pointer spilled to the stack) (`lost` per-CPU counter, logged); a UDP socket reports a destination again after 30 s (`udp_seen` LRU, 16,384). Socket filter on an `AF_PACKET` `SOCK_DGRAM` socket bound after the filter is attached: outgoing TCP / UDP whole, incoming TCP only without data or with SYN-ACK / FIN / RST, incoming SYNs dropped, incoming UDP only from port 53, loopback once (the received copy). `Joiner` holds observations without an owner up to 100 ms (UDP records come after the datagram), in order. Needs root or `CAP_BPF` + `CAP_PERFMON` + `CAP_NET_RAW`; with `[daemon] user` the daemon keeps exactly those on one thread (`privileges::Keeper`), which starts capture again after hibernation. CI: local action `.github/actions/linux-build-deps` (clang, libelf-dev, zlib1g-dev) in every Linux job that builds the workspace; `scripts/build/linux.sh run --privileged` for the eBPF tests in the build container | Implemented (phase 7 done 2026-11-25) |
| Fallback capture | libpcap (Linux, macOS) / Npcap (Windows) loaded at run time with `libloading` (no SDK at build time; `SCRIBE_LIBPCAP` overrides), non-blocking reads, `[sensor] interface` (`""` = Linux `any` or the first device that is up); no process attribution; `FallbackSensor` puts it behind the native sensors; rules in specs 8.4.1 | Implemented (phase 6) |
| UI technology | Tauri | Proposed |
| Crypto library | `ring` 0.17 — HKDF, AES-128-GCM and QUIC header protection (`ring::aead::quic`) for QUIC Initial decryption; most downloaded option (839M total, 197M in 90 days on crates.io, 2026-10-26) and needs Rust 1.66 | Decided |
| Async in interfaces | Boxed futures (`BoxFuture`), no `async-trait` crate | Decided |
| External dependencies | Added as each phase needs them; see the lists below | Decided |
| Formatting / lint | `cargo fmt`; `cargo clippy -- -D warnings` must pass | Decided |
| Line endings | LF everywhere (`.gitattributes`), binary fixtures marked binary | Decided |
| Time in production code | Read through the `Clock` interface so tests can control it | Decided |

**Minimum Rust version history**

| Version | Date | Reason |
|---|---|---|
| 1.70 | 2026-10 | Initial skeleton, matched the toolchain installed at the time |
| 1.89 | 2026-11-08 | Policy *follow dependencies* adopted; rusqlite (phase 1) and notify-rust (phase 11) need 1.89, tonic and proptest 1.88, tokio and clap 1.85 |
| ~~1.98 (expected)~~ | phase 7 | No longer expected: option 7B uses `libbpf-rs` (needs 1.82; `libbpf-sys` 1.89) instead of `aya` 0.16 |

**Libraries in use** (since phase 0): `tokio`, `serde`, `toml`, `thiserror`, `anyhow`, `clap`, `tracing`,
`tracing-subscriber`, `tracing-appender`, `tracing-journald` (Linux), `tracing-oslog` (macOS), `fs4`,
`libc` (macOS), `windows-sys` (Windows); tests: `proptest`, `tempfile`.

Also `serde_json`, `rusqlite` 0.43 (bundled SQLite, phase 1); the storage manager uses Tokio (`rt`, `sync`, `time`) and `tracing` (phase 2).

**Planned libraries** (add when implementing): `libbpf-rs` + `libbpf-cargo` (phase 7),
`windows`, `pcap`, `libfuzzer-sys` (fuzz workspace only). `ring` 0.17 is in use (`enrich`, `secrets`, `module-url`, `test-support`).

Local API (phase 10): `tonic` 0.14 with `tonic-prost` / `prost` 0.14; code generated by `tonic-prost-build` from a descriptor set that `protox` 0.10 compiles in Rust, so building needs **no `protoc`**; `hyper-util` and `tower` for the client connector; `tokio-stream` for the socket listener.

## 4. Crates and binaries

| Name | Kind | Purpose |
|---|---|---|
| `scribe-core` | lib | Flow events, modes, alerts, clock, sensor interface, `VERSION` |
| `scribe-enrich` | lib | `Enricher`: TLS ClientHello (SNI, ALPN, ECH), HTTP request heads and `Host`, DNS answers and cache, QUIC Initial decryption, security detection (full URL parsing is in `scribe-module-url`) |
| `scribe-secrets` | lib | Secret references (`file:`, macOS keychain, Windows DPAPI, Linux Secret Service), `read`, `store`, key generation |
| `scribe-sensor-linux` / `-windows` / `-pcap` | lib | Capture sensors; `-linux` has `record` (ring-buffer records), `owners` (join with packet observations) and `join` (hold queue, hit rate), built and tested on every system, and the Linux-only `EbpfSensor` (name `linux-ebpf`; `attribution()` reports the hit rate with no table reads); `-pcap` has `decode`, `flows` (tracker and `replay`), `file` (pcap reader) and `ffi` (run-time libpcap) |
| `scribe-process` | lib | Process attribution from the OS socket table (plan option P): `SocketTable` per system (Linux `/proc/net/*` + `/proc/<pid>/fd` + `/proc/<pid>/exe`; macOS `libproc` with `socket_fdinfo` fields read at SDK offsets, checked on arm64 and x86_64; Windows `GetExtended{Tcp,Udp}Table` with owner pid + `QueryFullProcessImageNameW`); `Resolver` (exact 5-tuple, then unconnected UDP, then local port; IPv4-mapped addresses as IPv4; table read again on a miss at most every 100 ms via `Clock`; paths cached per table read); `Attributed` sensor wrapper (thread between sensor and scribed; `NewFlow` and `Payload` without a pid; name `pcap` → `pcap+sockets`; `has_process_info` true; counts attributed / missed new flows). Scan budget (option 9B, 2026-11-25): each table read is timed through `Clock`; one over `SCAN_BUDGET` (50 ms) makes the next read wait 10× as long (`SLOW_FACTOR`, at most `MAX_REFRESH` 5 s), a fast one resets it to 100 ms. `Sensor::attribution()` (core, default `None`; `AttributionStats` with attributed, missed, scans, slow scans, last / max scan) feeds `Status.sensor.attribution` (API message `Attribution`, additive, `API_VERSION` stays 1) and the `process` row of `scribe daemon status`. `[sensor] process_lookup = true` (restart). The `fallback_sensor` critical metric now keys on a `pcap…` sensor name on Linux / Windows |
| `scribe-storage-api` | lib | `StateStore`, `EventSink`, `StorageFactory` |
| `scribe-storage-manager` | lib | Registry, writer task per sink (batching, retention), spool and replay, outage buffer, cache, health |
| `scribe-storage-sqlite` | lib | Default backend (feature `sqlite`, on by default); implemented, passes both conformance suites |
| `scribe-storage-postgres` | lib | Optional backend (feature `postgres`). Event sink implemented (option 12C): `tokio-postgres` 0.7 (`with-serde_json-1`) driven by a worker thread with its own current-thread tokio runtime (requests over an unbounded channel, replies on oneshots, so any executor can await them); one connection, reopened when closed. TLS: `tokio-postgres-rustls` 0.14 with `scribe_net::tls_config` (OS trust store); off-loopback servers always `Require` (+ host check by rustls), `disable` / `allow` refused (config check `plaintext_to_remote` too); loopback / Unix socket without TLS unless `require`. Options `url`, `credentials` (password via `scribe-secrets`), `schema` (`[a-z_][a-z0-9_]*`, created, `search_path`; tests use one per run). Migrations under `pg_advisory_lock`, each `BEGIN … INSERT INTO schema_migrations … COMMIT`. Writes: one `WITH … INSERT … SELECT unnest(…)` statement for events and metrics (atomic). Times stored at millisecond precision like SQLite. State store: stubs; `[storage.state] kind = "postgres"` is refused in config until it exists |
| `scribe-storage-conformance` / `scribe-sensor-conformance` | lib | Shared test suites |
| `scribe-test-support` | lib + bin | Test doubles, packet builders, `gen-fixtures` |
| `scribe-tests` (`tests/`) | lib + test bins | Cross-crate smoke, integration and scenario tests; not published |
| `scribe-policy` | lib | `Policy::decide`: modes, scoring (built-in and module signals), threat lists, dedupe and acknowledgement, learn time limit; no I/O |
| `scribe-alerts` | lib | `Dispatcher` (a thread, a queue of 256 and a `Throttle` per output), `LogOutput`; `WebhookOutput` behind feature `webhook` (on in the daemon; off in the CLI, which uses only `Throttle` and so stays free of ring's C code) |
| `scribe-net` | lib | Outgoing HTTPS for webhooks and threat lists: own small HTTP/1.1 client on rustls 0.23 (ring) with `rustls-platform-verifier` (OS trust store) or a leaf-certificate pin; https only except loopback; same-origin redirects (≤ 3, POST only on 307 / 308); connect / read / write timeouts; body cap; no proxy; `signature()` for `X-Scribe-Signature` |
| `scribe-module-api` | lib | `Module`, `FlowHook`, `Source`, manifest, context, notes, records, metric samples (section 9b) |
| `scribe-module-url` | lib | URL tracking module, feature `url` of `scribe-daemon`, on by default |
| `scribe-module-conformance` | lib | Suite every module must pass |
| `scribe-api` | lib | gRPC protocol (`proto/scribe/v1/api.proto`, package `scribe.v1`, service `Scribe`), socket transport, caller identity and access policy; features `server` / `client` generate only the side needed |
| `scribe-daemon` / `scribed` | lib + bin | The service: `config` (with `reload`), `logging`, `pipeline`, `chain`, `security`, `service`, `privileges`, `modules` and `app` in the library; `main.rs` is a thin wrapper |
| `scribe-cli` / `scribe` | lib + bin | The command line client (`clap`) |

Only SQLite and Postgres storage backends are in scope. ClickHouse, OpenSearch, file sinks and
external gRPC storage plugins were discussed and **deliberately left out**.

## 5. Storage

| Item | Value | State |
|---|---|---|
| Roles | Exactly one **state store** (hosts, counters, baselines, alert state); zero or more **event sinks** (flow / alert / audit records) | Decided |
| Backend selection | `kind = "sqlite"` / `"postgres"` in config, resolved by the registry | Decided |
| Counter updates | Always as deltas (`n = n + excluded.n`), never read-modify-write | Decided |
| Security flags | `tls_seen` / `plaintext_seen` only ever turn on | Decided |
| Record schema version | `SCHEMA_VERSION = 4` (v1 and v2 rows still readable) | Decided |
| Row layout | `scribe_storage_api::codec`: kind, module, host, schema, JSON payload per event; epoch-ms times; shared by SQLite and Postgres | Implemented |
| SQLite backend | `rusqlite` 0.43 bundled; opened on first use, WAL, `synchronous = NORMAL`, 5 s busy timeout; migrations per transaction into `schema_migrations` + `user_version`, newer schema refused; metric samples in `metrics`, everything else in `events`; queries merge both by time (`since` inclusive, `until` exclusive) | Implemented (phase 1) |
| SQLite timestamps | Unix epoch **milliseconds** (INTEGER); booleans as 0/1 | Decided |
| Postgres types | `TIMESTAMPTZ`, `BOOLEAN`, `INET`, `JSONB` payloads | Decided |
| Event payloads | JSON text (SQLite) / JSONB (Postgres) | Decided |
| SQLite `max_batch` | 1000 | Decided |
| Postgres `max_batch` | 5000 | Decided |
| Sink write batching | Writer task per sink: `batch_max_events = 500` (capped by `max_batch`), `batch_max_wait = "1s"`; queue 1,024 messages, full queue drops and counts | Implemented (phase 2) |
| Host cache | LRU in front of the state store (`CachedState`): `storage.cache.max_hosts = 50000`, `max_memory = "32MiB"`; baselines cached per profile; `clear_cache` | Implemented (phase 2) |
| State store outage | `BufferedState`: backend / config errors start buffering; writes kept in order within `storage.buffer` (`max_events = 50000`, `max_memory = "32MiB"`), oldest dropped and counted; replay with back-off 1 s → 60 s; `Data` errors are not buffered | Implemented (phase 2) |
| Spool | `<spool dir>/<sink>/<seq>.jsonl` (stored rows, 4 MiB segments), ordered at-least-once replay with back-off 1 s → 60 s; shared `max_size = "512MiB"`, `min_free_disk = "5%"`; oldest dropped and counted; replayed after restart | Implemented (phase 2) |
| Size values | Absolute (`32MiB`, 1024-based) or percentage: memory = % of RAM, disk = % of the volume; resolved at startup and logged; absolute by default for predictable memory (NFR: < 100 MB) | Draft default |
| Retention | Per sink, e.g. `30d`; hourly `EventSink::delete_before` for sinks without native retention | Implemented (phase 2) |
| Credentials | OS keychain (macOS), DPAPI (Windows), Secret Service (Linux) or a root-only file; never plain config | Proposed |
| Migrations | Files in `crates/storage-*/migrations/`, idempotent (`IF NOT EXISTS`); a snapshot per released schema in `testdata/db/`, never edited afterwards | Decided |

## 6. Configuration (`scribed`)

Draft v1 config with every option and its default: [config/scribe.toml](../../../config/scribe.toml)
(`version = 1`; an empty file behaves the same). It replaced `config/scribe.example.toml`. Loading is planned for phase 0.
Full option table: `workfiles/specs.md` section 9.1.

| Item | Value | State |
|---|---|---|
| Lookup order | `--config`, then `SCRIBE_CONFIG`, then the OS default; no file = built-in defaults; a file named by flag or variable must exist | Decided (implemented) |
| Relative paths | Resolve against `data_dir`, which must be absolute | Decided (implemented) |
| Config code | `crates/daemon/src/config/` (model, load, resolve); built-in defaults equal `config/scribe.toml`, enforced by a test | Decided (implemented) |
| Config checks | Unknown keys and bad values rejected with line and column; sqlite needs `path`, postgres needs `url` without a password; sink names unique; threat list has exactly one of `path` / `url`, `refresh` only with `url`; storage kind must be built in | Decided (implemented) |
| Empty `log.file` | `""` writes to stderr | Decided (implemented) |
| Log rotation | `daily`: `scribed.<date>.log` with a `scribed.log` symlink to today's file (Unix); `size`: `scribed.log` → `.1` … `.<keep>`; `keep` rotated files kept | Decided (implemented) |
| Log fallback | A log file or system log that can't be used falls back to stderr with a warning; scribed still starts | Decided (implemented) |
| System log | journald with identifier `scribed` (Linux); unified logging subsystem `com.scribe.daemon` (macOS) | Decided (implemented) |
| Windows system log | `log.output = "system"` / `"both"` rejected on Windows until the installer registers the Event Log source (phase 13) | Decided (implemented) |
| Durations | `45s`, `10m`, `1h`, `7d` | Draft default |
| Linux | config `/etc/scribe/scribe.toml`, data `/var/lib/scribe/`, log `/var/log/scribe/scribed.log`, system log journald / syslog | Decided |
| macOS | config and data `/Library/Application Support/scribe/`, log `/var/log/scribe/scribed.log`, system log unified logging (optional, `log.output`) | Decided |
| Windows | config `<install dir>\scribe.toml` (next to `scribed.exe`); data `<install dir>\data\` | Decided |
| Windows logs | file `<install dir>\logs\scribed.log` by default, or the Event Viewer when `log.output = "system"` | Decided |
| Windows installer | MSI never overwrites or deletes `scribe.toml`, `data\`, `logs\`; grants the service write access to them | Proposed (phase 13) |
| Log options | `level = "info"` (`SCRIBE_LOG` overrides), `format = "text"`, `rotate = "daily"`, `max_size = "50MiB"`, `keep = 14`, `output = "file"` (`file` \| `system` \| `both`) | Draft default |
| Postgres `url` | connection string **without** password | Decided |
| Postgres `credentials` | secret reference: `keychain:`, `dpapi:`, `secret-service:`, `file:` | Proposed |
| URL privacy | `[modules.url] query` (`privacy.url_query` is a deprecated alias for one version): `full`, `redact_values` (**default**), `strip`, `path_only`, `hash` (`?<hash:xxxxxx>`, HMAC-SHA256 with a per-install key via `ring`); scheme and host always kept, user info always removed; applies to new data only. Rules and examples: `workfiles/specs.md` 12.2 | Decided |

## 7. Enrichment

| Item | Value | State |
|---|---|---|
| Hostname sources, in priority | TLS SNI (TCP or QUIC Initial) → HTTP `Host` header → a name the sensor reported → DNS cache (IP → queried name); DNS answers come from raw responses (pcap, eBPF) or OS-decoded answers (ETW) | Implemented (`Enricher`; all fixtures pass end to end) |
| DNS cache | Keyed by IP, honours record TTL; CNAME chains map back to the **queried** name | Decided |
| TLS detection | TCP: first bytes `0x16 0x03 ..` = TLS; empty = unknown; anything else = plaintext. UDP: a v1 / v2 long header = QUIC, anything else = plaintext. Never by port | Implemented |
| ECH | Only the outer public name is visible; flagged `ech: true` | Decided (fixtures) |
| DNS-over-HTTPS | Later lookups are invisible; flows fall back to IP | Decided |
| QUIC | SNI from client Initial packets, QUIC v1 and v2 (RFC 9369; draft versions unsupported): derive keys from the Destination Connection ID and the version salt (HKDF-SHA256), remove header protection (AES-128-ECB), decrypt (AES-128-GCM), reassemble CRYPTO frames by offset across Initials of the first DCID (`InitialReassembler`, 64 KiB cap, one hello per flow), then parse the ClientHello. Single-datagram hellos are handled by `Enricher::enrich` (UDP → `Protocol::Quic`); multi-datagram ones need the phase 5 pipeline to keep a reassembler per flow | Implemented |
| QUIC crypto | `ring` 0.17 in `enrich` and `test-support` (two separate implementations); both RFC 9001 and RFC 9369 Appendix A packets decrypt, and the test-support builder reproduces them byte for byte; fixtures `quic_initial`, `quic_split_hello`. ring's C code means local macOS cross-checks cover only crates without it; CI checks the rest natively | Decided |
| Full URL | Plaintext HTTP only | Decided |

## 8. Counting

Three counters per host and per process + host, plus hourly buckets per host (schema v4, kept `90d`):

- **Connections / flows:** each TCP connection or UDP / QUIC flow.
- **Requests:** plaintext HTTP requests only (not visible inside TLS).
- **Bytes out.**

## 9. Local API, CLI and services

| Item | Value | State |
|---|---|---|
| Local API | gRPC (`tonic`) over a Unix socket (Linux, macOS) or named pipe (Windows); `API_VERSION` 1 in `Status.api_version`; times as epoch ms (`*_ms`), durations in seconds (`*_s`). `scribe_api::transport::{bind, serve, connect, channel, Listener}` picks the platform, so the daemon and clients have no platform code | Implemented (Unix socket step 1, named pipe step 6) |
| New crates | `crates/policy` (`scribe-policy`, no I/O), `crates/alerts` (`scribe-alerts`), `crates/api` (`scribe-api`, features `server` / `client`) + `proto/scribe/v1/api.proto` | Decided (option A, `workfiles/specs.md` 7.2) |
| API access | Socket readable only by the owner and the admin group; caller identity from the socket (`SO_PEERCRED`, `getpeereid`, pipe client token): read calls for the `scribe` group, control calls (reset, hibernate, wakeup, mode, ack, baseline) for root / Administrators and `scribe-admin`; control calls logged and stored as `audit` events | Proposed |
| CLI commands | `status`, `hosts [--filter]`, `mode <learn\|caution\|alert>`, `alerts`, `alerts ack <id>`, `baseline`, `baseline add\|rm <host>…` (`remove` alias), `export [-o file]` (one JSON document `{hosts, baseline}`; file created `0600` by the CLI), `modules`, `version` / `--version`; `--json` on the listing commands prints the API messages (`serde::Serialize` derived on every generated message); global `--socket`, then `SCRIBE_SOCKET`, then the OS default; exit codes 0 / 1 / 2. Messages: unreachable → *scribed is not running or its socket is not reachable (<path>: <why>)*; socket not readable → *permission denied: the scribe group may read it*; refused control call → *permission denied: …*; API version mismatch → a warning on `status` | Implemented (phase 10 step 4) |
| `scribe daemon` commands | `status [--json] [--watch <interval>]` (run state, live counters, critical metrics first marked `!`, red on a terminal; `scribe status` is its short form; `--watch` redraws until Ctrl-C, with `--json` one object per line), `health [--json] [--timeout 2s]` (prints `healthy`, `degraded: …` or `unhealthy: …` on stdout; exit 0 healthy or degraded, 1 unhealthy or unreachable; also `grpc.health.v1`), `reset [--counters] [--caches] [--config]` (none = all; never touches stored history), `hibernate [--for <duration>]`, `wakeup`; aliases `hybernate` (shown in help), `sleep`, `wake` | Implemented (phase 10 step 4) |
| Service integration | systemd `Type=notify` (`READY=1`, `STOPPING=1`, `ExecReload` → SIGHUP; `packaging/linux/scribed.service`), launchd plist `packaging/macos/io.github.savex.scribed.plist` (foreground, SIGTERM), Windows `scribed --service` via `windows-service` 0.8 + `packaging/windows/install-service.ps1`; release archives carry them under `service/`; `[daemon] user` (Unix) drops to that user after storage and sensor are open, `data_dir` must belong to it; on Linux one thread keeps `CAP_BPF` / `CAP_PERFMON` / `CAP_NET_RAW` (`PR_SET_KEEPCAPS`, then `capset`; capabilities are per thread, so all others have none) and runs sensor restarts, and `RLIMIT_MEMLOCK` is lifted while root; root-only tests that drop privileges run alone (`--exact`, own process); hardened units, users and groups in phase 13 | Implemented (phase 5) |
| Config reload | `Command::Reload` and SIGHUP re-read the start file; live: `mode` (when the file's value changed), `profile`, `[policy]` (threat files re-read), modules, `[daemon]`, log level (not over `SCRIBE_LOG`); restart: `data_dir`, storage backends, sinks, storage limits, log file / output / format / rotation; all-or-nothing; `audit` event per reload | Implemented in the daemon (phase 5; specs 8.5.2) |
| Run states | `running`, `degraded` (health result), `hibernating` (sensor detached, nothing recorded or alerted, API and spool replay keep running, `learn_for` paused, `audit` event at start and end, not kept across a restart), `stopping`; daemon side implemented: `Pipeline::hibernate` / `wakeup`, `serve_controlled` + `Command`, `[daemon] max_hibernate` (`4h`, `""` unlimited with a warning); `hibernated` alert at `0.0.0.0:0` with a `daemon` note | Implemented in the daemon (phase 5; restart behaviour is open question 9) |
| Alert outputs | `[alerts] log = true`, `max_per_minute = 30` (per output, fixed one-minute window from the first alert, the held-back count reported once through `AlertOutput::suppressed`; `0` = unlimited); live on reload. `AlertOutput::notify` returns `Result`; the dispatcher counts sent / failed / suppressed / dropped per output, logs a failure once until it works again, and gives outputs 3 s at shutdown. Storage and `WatchAlerts` always get every alert. OS notifications are not a daemon output: a system service can't reach a desktop session on any of the three systems, so the `scribe notify` agent in the user's session follows `WatchAlerts` | Implemented (phase 11 step 1) |
| Webhook output | `[[alerts.webhooks]] name, url, secret, pin_sha256, timeout = "10s"` checked at load (`scribe_net::checked_url`, `SecretRef`, `parse_pin`, 1–60 s, names unique and not `log`); secret read when the outputs are built (start: refused with the error; reload: rejected as a whole, outputs built before anything applies). Body JSON (`type` `alert` / `suppressed`, `version` 1, `machine` = host name, `scribe_version`, `sent_ms`, alert fields, `notes` as stored), `X-Scribe-Signature: t=<unix s>,v1=<hex HMAC-SHA256("<t>.<body>")>`; 2xx = success; retries after 1 s and 4 s for transient network errors, 429 and 5xx | Implemented (phase 11 step 3) |
| `scribe notify` | CLI agent (feature `notify`, default on; `notify-rust` 4.19 with `z`: D-Bus in pure Rust, Notification Center, toasts): one notification per alert, title `scribe: <reason in words>`, body host (dst), process, URL note, `score N · scribe alerts ack <id>`; `--max-per-minute 10` (`Throttle`), `--min-score` (not for `hibernated`), `--print`; reconnects 1 s → 60 s, subscribes before listing missed alerts (`since_ms` of the last one, ids above the last); fatal only on permission denied / server check. Autostart: systemd user unit, launchd agent (`Aqua`), HKCU Run key via hidden PowerShell (`packaging/`, shipped in release archives). `scribe alerts --watch [--json]` prints the stream. `MockApiServer::raise` / `watchers` feed `WatchAlerts` in tests and end streams on stop | Implemented (phase 11 step 2) |
| Alert state at start | `StateStore::alert_states()` (all, by key; default `NotImplemented`; conformance case); `scribed` restores acknowledged keys and unacknowledged ones inside `dedupe_window` with `Policy::restore_alert(alert_from_key(key, last_alerted), acknowledged)`; a key raised since start wins | Implemented (phase 10 step 5) |
| `scribe audit verify` | API `VerifyAudit` (read call): flushes the sinks, reads every audit and alert record, runs `chain::verify` with the daemon's key and compares with the last sealed sequence. Problems: `gap`, `mismatch` (the record after a changed one), `unlinked`, `missing_tail` (sealed but not stored). Records before `first_seq` aged out by retention aren't a problem. CLI exits 1 when anything is wrong; `--json` | Implemented (phase 10 step 5) |
| `[api]` config | `socket` (`""` = OS default; absolute path or `\\.\pipe\…`), `admin_group` (`"scribe-admin"`); both need a restart. `serve()` opens the socket from config before dropping privileges; `serve_full` + `ServeOptions { commands, api_socket }` lets tests pick a temp socket or none (`serve_with` / `serve_controlled` run without the API). A socket that can't be bound (in use, no permission) is a warning: scribed keeps capturing without the API, and only the daemon that bound the socket removes it | Implemented (phase 10 step 2) |
| API in the daemon | `crates/daemon/src/api.rs`: pipeline state through `Command::Describe` (a `Snapshot`: status, sensor, config path and load time, flows/s and events/s over 60 s, module drops); storage read directly (`Arc<Storage>`, `Storage::query` for alerts). Alert `id` = chain sequence; `acknowledged` from the alert state. `WatchAlerts` from a broadcast of sealed alerts (256 kept). Streams end when scribed stops; open calls get 3 s. `grpc.health.v1` (`tonic-health`) for `""` and `scribe.v1.Scribe`, updated every 2 s. Critical kinds: `sensor_detached`, `state_unhealthy`, `sink_unhealthy`, `drops`, `sink_spooling`, `spool_high` / `buffer_high` (over 80%), `state_buffering`, `fallback_sensor`, `attribution_low` (fewer than half of at least 100 new flows got a process from the socket table; `ATTRIBUTION_LOW` 0.5, `ATTRIBUTION_MIN_FLOWS` 100), `module_failed`, `hibernating`. Health: unhealthy for a detached sensor (not hibernating), a down state store or a loop that doesn't answer in 2 s; degraded for any other critical item | Implemented (read calls, phase 10 step 2) |
| API control calls | `SetMode`, `EditBaseline` (lower-cased, trailing dot dropped; spaces, `/ \\ @ ? #`, control characters and names over 253 bytes refused; 1000 hosts per call; added as `manual`), `AckAlert` (by chain sequence; `not_found` otherwise; writes the alert state once, `changed = false` after), `Reset` (`config` first, so a rejected file resets nothing and fails with `invalid_argument` and its line; no flag = config, counters, caches), `Hibernate` (`for_s = 0` refused), `Wakeup`. Each runs on the main loop as a `Command` (`SetMode`, `EditBaseline`, `Acknowledge`, `Reset` with `caller`, `Reload`, `Hibernate`, `Wakeup`) and writes an `audit` event naming the caller (`alice (uid 1000, pid 4242)`), no-ops included; a refusal is logged and stored through `Command::Audit` (`refused SetMode from …: permission denied: …`). A learn mode set while hibernating starts its countdown at wakeup. `StateStore::remove_from_baseline` (default `NotImplemented`; SQLite, memory store, cache, outage buffer; conformance case) | Implemented (phase 10 step 3) |
| Config reload | `scribe daemon reset --config` or SIGHUP: same file, same checks, all-or-nothing; live: mode, profile, `[policy]`, `privacy`, log level and format, alert outputs, retention, batching, limits; restart needed: `data_dir`, state store, adding / removing sinks, sensor, log file / output / rotate, API socket | Proposed (specs 8.5.2) |
| Linux service | systemd unit `scribed` | Proposed (used by e2e script) |
| macOS service | launchd `com.scribe.daemon`; uninstaller `/Library/Application Support/scribe/uninstall.sh` | Proposed (used by e2e script) |
| Windows service | `scribed` | Proposed (used by e2e script) |
| Privileges | Runs as root / SYSTEM, drops privileges after the sensor starts | Proposed |
| `scribed` flags | `--config <path>`, `--check-config` (prints the effective config as TOML, paths absolute, percentages explained), `--set-secret <reference>` (stores standard input, one trailing newline dropped; with `--generate` a new random 32-byte key as hex, printed for the receiver; exit 2 on errors), `--version` / `-V` | Decided (implemented) |
| `scribed` exit codes | 0 success, 1 runtime failure, 2 usage or configuration error (including a bad `SCRIBE_LOG`) | Decided (implemented) |
| `scribed` lifecycle | arguments → config → logging → create data and spool folders → storage via registry + `migrate()` (a not-implemented backend only warns) → wait for Ctrl-C or SIGTERM → flush sinks → exit 0. Windows service-manager stop arrives with phase 5 | Decided (implemented) |

## 9a. Security (proposed)

Full design: `workfiles/specs.md` 12.1.1. Locally, who is calling matters more than encryption (identity from the OS); everything leaving the host uses TLS plus authentication.

| Item | Value | State |
|---|---|---|
| TLS library | `rustls` with the `ring` provider (no OpenSSL); tonic `tls-ring` if TLS is ever needed | Proposed |
| API socket | `/run/scribe/api.sock` (Linux), `/var/run/scribe/api.sock` (macOS), `\\.\pipe\scribed` (Windows); `SCRIBE_SOCKET` overrides it for clients. Directory `root:scribe` `0750` (`bind` creates a missing one `0750`); socket file mode not relied on; a stale socket is replaced, a live one or a non-socket refused | Implemented (Unix; group set by the installer, phase 13) |
| Named pipe | `\\.\pipe\scribed`; `first_pipe_instance(true)` (a held name is refused: *in use*), `reject_remote_clients(true)`; access list from SDDL: SYSTEM, Administrators and the daemon's own user `GA`, the `scribe` and admin groups (when they exist) `0x0012019b` (read and write data, not `FILE_CREATE_PIPE_INSTANCE`, so no one else can add instances). Caller identity from the client process token (`GetNamedPipeClientProcessId` → `OpenProcessToken`, no impersonation): user `DOMAIN\name`, enabled groups by name with and without domain; privileged = SYSTEM or an enabled (elevated) Administrators group. Clients check the server process with `GetNamedPipeServerProcessId`: SYSTEM, or with `RootOrSelf` the same user; a busy pipe is retried every 20 ms | Implemented (phase 10 step 6; tested on the Windows CI runner only) |
| Caller identity | From the OS once per connection (`peer_cred`: uid, gid, pid; user and group names via `getpwuid_r` / `getgrouplist`), attached as `scribe_api::access::Caller` in tonic request extensions; never from message fields. `AccessPolicy::check` gives `permission denied` for control calls outside root / `scribe-admin` | Implemented (Unix) |
| Server check by clients | `scribe_api::ServerCheck`: path must be a socket owned by root (`Root`) or by the calling user itself (`RootOrSelf`, the CLI default: a user can't be fooled by their own socket, and test or development daemons run unprivileged); a pipe server must run as SYSTEM (or the same user with `RootOrSelf`) | Implemented |
| API limits | `scribe_api::limits`: 4 MiB messages both ways, 30 s per call, 16 calls at once and 8 streams per connection | Implemented |
| `export` | Daemon streams; CLI writes the file as the caller; daemon never writes client-supplied paths | Proposed |
| Silencing controls | `hibernate`, mode, `reset`: admin only, audited (refusals too); `hibernate` capped by `daemon.max_hibernate` (default `4h`, also applies without `--for`) and raises a `hibernated` alert in every mode | Proposed |
| UI control calls | Elevation via polkit / Authorization Services / UAC; strict CSP, no remote content | Proposed |
| XPC | Code-signing requirement both ways (Team ID + bundle ID); schema, size limits, fuzzed decoder | Proposed (only with option 9A, later) |
| Privilege split | Privileged part only loads / attaches sensors; parsers run unprivileged. Linux (phase 7): one keeper thread with `CAP_BPF` / `CAP_PERFMON` / `CAP_NET_RAW` starts capture, the rest of scribed runs as `[daemon] user` without capabilities; executable paths come from the kernel. Windows (phase 8) open | Linux implemented; Windows proposed |
| systemd hardening | `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `CapabilityBoundingSet`, `RestrictAddressFamilies`, `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute` | Proposed |
| Postgres transport | `tokio-postgres-rustls`, default `verify-full`; `disable` / `prefer` rejected for non-loopback hosts; optional client certificates | Proposed |
| Postgres role | Sink role `INSERT` only; one role per host, row-level security on `host_id` | Proposed |
| Webhook | HTTPS only (except loopback), no cross-host redirects, `X-Scribe-Signature: t=<ts>,v1=<hmac-sha256>`, secret by keychain reference | Proposed |
| Threat lists | HTTPS, optional pinned `sha256` or `minisign` key, keep last good list, entry cap | Proposed |
| File modes | `0600` / `0640 root:scribe-admin`; startup refused if config, `data_dir` or `file:` credential is group/other-writable | Proposed |
| Encryption at rest | Default: file modes + full-disk encryption; optional `storage.encrypt = true` (SQLCipher + AES-256-GCM spool, key in OS secret store) | Proposed |
| URL hash key | `[modules.url] hash_key` secret reference; default `file:<data_dir>/url_hash.key` (32 random bytes as hex, `0600`, created on first start); HMAC-SHA256 via `ring`, first 6 hex digits; no key → the module does not start | Decided |
| Tamper evidence | Sequence number + `prev_hmac` on audit and alert records (one chain; HMAC-SHA256 with `audit.key` in `data_dir`; state in `audit.chain`; `chain::verify`); `audit` events for start, clean stop and unclean stop (`scribed.running` marker); StrictModes refuses a group/other-writable config file or `data_dir` (Unix); heartbeats to the remote sink in phase 12 | Implemented (phase 5), heartbeats Proposed |
| Remote API | None; Postgres sink for fleet view, SSH forwarding for remote control; if ever added: off by default, client certificates only | Proposed |
| Proposed config keys | Postgres `sslmode`, `ca`, `client_cert`, `client_key`; `[[policy.threat_lists]]` `sha256` / `minisign_key`, `max_entries`; `storage.encrypt`. Not in config v1 yet; each lands with its phase (specs 9.1.1) | Proposed |
| Security work per phase | 5: StrictModes, hibernate cap, audit chain; 7–8: privilege split, service SID (XPC signing only with option 9A); 10: API access and limits; 11: HTTPS, signed webhooks, threat-list checks; 12: Postgres TLS, roles, heartbeats; 13: service hardening, release signing, optional encryption at rest; 14: `cargo deny` / `audit`, pinned Actions, review | Proposed (plan.md) |
| License | MIT OR Apache-2.0 for the workspace (`LICENSE-MIT`, `LICENSE-APACHE`, `license.workspace = true` in every crate, fuzz included); eBPF C sources `GPL-2.0-only OR BSD-2-Clause` (SPDX headers; `SEC("license")` "Dual BSD/GPL" for GPL-only helpers and fentry); contributions under the same terms (readme); both files in every release archive (Release workflow, `scripts/build/common.sh`, `windows.ps1`); dependencies limited to permissive licences by `deny.toml` | Decided (2026-11-25) |
| Release integrity | Signed `SHA256SUMS`, build provenance attestation (Proposed); `cargo deny` (`deny.toml`: RustSec advisories, licenses, bans, sources; it covers what `cargo audit` checks) in the Tests job *Dependencies*; every Action pinned by commit SHA with the version in a comment (no Dependabot: no scheduled automation, see section 11; re-pin by hand with `gh api repos/<owner>/<repo>/commits/<tag>`); `permissions: contents: read` except Release and Bump version; workspace `publish = false` | Implemented (supply chain, 2026-11-25) |

## 9b. Modules (implemented in phase 0b)

Full design: `workfiles/specs.md` 7.4 (7.4.9 lists what changed from the draft). New functionality is added as a module, without editing `core`, `storage-api`, the schemas, the config model or the API.

| Item | Value | State |
|---|---|---|
| Packaging | Compiled in, chosen by Cargo feature on `scribe-daemon` (`url` default on, `kperf` later); `modules::builtin()` lists `ModuleSpec { id, make }`; no `dlopen` | Implemented |
| Interface | `scribe-module-api`: `Module` (`manifest`, `configure(&ConfigDoc) -> Reload`, `start(ModuleContext)`, `pause`, `resume`, `stop`, `health`, `effective_config`, optional `flow_hook` / `source`), `Manifest::validate` (id `[a-z][a-z0-9_]*`, kinds and metrics `<id>.<name>`) | Implemented |
| Module config | `ConfigDoc::section::<T>(id)` deserializes `[modules.<id>]` from the spanned file, so errors keep line and column; `ConfigDoc::get` for keys elsewhere; `span_of` for errors found later | Implemented |
| Outputs | Flow notes (`FlowEvent.notes`, keyed by module id), module records (`StoredEvent::Module`, `EventKind::Module("<id>.<name>")`), metric samples (`StoredEvent::Metric`, `EventKind::Metric`), module state (`StateStore::module_state` / `put_module_state`); types `Notes`, `ModuleRecord`, `MetricSample` live in `scribe-core`; kinds are `Cow<'static, str>` | Implemented |
| Sensor output | `Observation { event, head }`, `head` at most `HEAD_MAX` = 4 KiB; `FlowKind::Payload` for more client bytes on an existing flow (was `Request`) | Implemented |
| Host | `ModuleHost`: hook time budget 1 ms (over-budget calls counted), panic switches off only that module (health degraded), sources ticked on their interval, pause / resume / reconfigure / stop; output through `OutputQueue` (10,000 items, drops counted), drained to storage once a second until the pipeline (phase 5) | Implemented |
| Policy signals | `Signal { reason: "<id>.<reason>", detail }`, scored from `[policy.scores]`; policy stays I/O-free | Decided (used from phase 4) |
| Payload | Bytes past the ClientHello / `Host` header kept only when an enabled module declares `needs.payload` | Decided (sensors honour it from phase 6) |
| Kernel probes | Only through the sensors' `ProbeHost`, loaded in the privileged part; modules run unprivileged | Proposed (with the native sensors) |
| Config | `[modules] enabled = ["url"]`; `[modules.<id>]` checked by the module; unknown, duplicate or not-built ids are errors; sink `events` accept `metric` and enabled modules' kinds | Implemented |
| API / CLI | `ListModules`, `GetModule` (every built module, disabled ones with their manifest version); per-module `proto/scribe/v1/modules/<id>.proto` (package `scribe.v1.modules.<id>`) compiled by the module crate's own `build.rs` (`protox`) behind its `server` / `client` features; the daemon adds a module's service to the API only while it is enabled, reading records through `scribe_module_api::RecordReader` (daemon: `StoredRecords` over the sinks); the CLI's `<id>` feature adds the module's `clap` subcommand, and an `unimplemented` answer becomes *module <id> is not enabled in this scribed* (exit 1). URL module: service `Url.List(host, limit ≤ 10000, default 100, since)`, `scribe url list [--host] [--limit] [--since] [--json]` | Implemented (phase 10 step 6) |
| Schema | v2: migration `0002_modules.sql` (`events.module`, free `kind` with `<module>.%` check, `metrics`, `module_state`); snapshots `sqlite/v2.db`, `postgres/v2_seed.sql`; `build.sh` never rewrites an existing snapshot without `--force <version>` | Implemented |
| Schema v3 | Migration `0003_processes.sql`: `hosts.unresolved` (sticky; IP hosts set on migration), `process_hosts (process, host)` counters updated with the host in one transaction from `HostDelta.process`; `StateStore::process_hosts`; alert payloads keep `dst_port` and `notes`; snapshots `sqlite/v3.db`, `postgres/v3_seed.sql` | Implemented (phase 5) |
| Schema v4 | Migration `0004_hours.sql`: `host_hours (host, hour)` (hour start, epoch ms / `TIMESTAMPTZ`) with connections, requests and bytes, added to by every `upsert_host` with a non-zero delta (`hour_of(seen_at)`); `StateStore::host_hours(host, since)` (oldest first, `since` counts from the start of its hour) and `prune_host_hours(before)` (defaults `NotImplemented`; conformance case); `[storage.hours] keep = "90d"` (`""` = forever, needs a restart), pruned at start and every hour; API `ListHostHours` (default last 24 h), `scribe hosts --hourly <host> [--since 7d]`; snapshots `sqlite/v4.db`, `postgres/v4_seed.sql` | Implemented (phase 10 step 5) |
| Conformance | New modules must pass `scribe-module-conformance` (`ModuleCase` + `run_module_suite`); test doubles `TagModule`, `TicksModule`, `NoopModule`, `MisbehavingModule` (7 faults), `RecordingEmitter` in `scribe-test-support` | Implemented |
| URL module | `scribe-module-url`: manifest (`url.request` schema 1, read call `list`, needs payload), `[modules.url] query`, deprecated `privacy.url_query` honoured (error if both disagree), hook notes the URL, records `url.request`, counts `requests.<host>` in module state; parser `parse::request_url` is a stub until phase 3 | Partly |

## 10. Versioning and releases

| Item | Value | State |
|---|---|---|
| Source of truth | Git tags `vMAJOR.MINOR.PATCH[-PRERELEASE]` | Decided |
| `Cargo.toml` version | Always equals the latest release tag | Decided |
| Latest version | The **highest** `v*` tag by SemVer precedence (`0.1.0-alpha.1` < `0.1.0` < `0.1.1`), not the nearest one; the next version builds on the highest of that tag, `Cargo.toml` and the newest `changelog.md` section, so unpushed or unfetched tags can't send it backwards; a version that isn't newer is refused | Decided (`scripts/version.sh highest` / `next` / `newer`) |
| Sync check | `scripts/version.sh versions` compares tag, `Cargo.toml` and `changelog.md`; Bump version, Version tracking and Tests warn when they differ | Decided |
| Changelog on release | Bump version turns Unreleased into `## [X.Y.Z] - date` and updates the links (`scripts/version.sh changelog`) | Decided |
| Binary version | `1.2.0` on a tag, `1.2.0+3.gabc1234` after 3 commits, `<cargo>+g<sha>` with no tag; no dirty marker | Decided (`crates/core/build.rs`) |
| Override | `SCRIBE_VERSION` env var (release builds) | Decided |
| Bump after a pre-release | Same-level bump finalizes it (`2.0.0-rc.1` + major → `2.0.0`) | Decided (`scripts/version.sh`) |
| First releases | `v0.1.1` (2026-11-08, tag only local, never pushed; superseded), `v0.1.0-alpha.1` (2026-11-22, Bump version started from 0.0.0 because no tag was on GitHub) and `v0.2.0` (2026-11-23, after phase 10; first GitHub release, Release run `45322623374`) and `v0.3.0-alpha.2` (2026-11-25, milestone M1 plus option P, supply-chain checks and the Postgres sink; minor bump with a pre-release label because `0.2.0-alpha.2` would sort below `0.2.0`) | Recorded |
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
- No scheduled (nightly) runs; the user chose manual triggers. That also rules out Dependabot schedules: Action pins are updated by hand.

## 12. Testing

| Item | Value | State |
|---|---|---|
| Test levels | unit, isolated component, contract / conformance, integration, end-to-end, non-functional | Decided |
| Test doubles | `FakeSensor`, `FakeClock`, `MemoryStore`, `MemorySink`, `FaultySink`, `RecordingAlertSink`; `MockApiServer` + `Scenario` (feature `mock-api`: serves a UI mock scenario over the real transport, `extends` merged, `generate.hosts` deterministic, control calls change its state, no access checks; binary `scribe-mock-api <scenario> <socket>`). UI mock files use the protocol's JSON (`*_ms` times; `serde::Deserialize` with `default, deny_unknown_fields` on every message) and a smoke test keeps them in step | Implemented |
| New storage backend | Must pass the storage conformance suite before it is registered | Decided |
| New sensor | Must pass the sensor conformance suite | Decided |
| Sensor event deadline | Each expected event within **1 s** | Decided (`SuiteOptions`) |
| Local test server timeout | **5 s** | Decided |
| Postgres test DB | `postgres://scribe:scribe@localhost:5432/scribe_test` (`SCRIBE_TEST_POSTGRES_URL`), `postgres:16` in CI | Decided |
| Fuzz run time | 1800 s per target | Decided (workflow default) |
| Linux kernel matrix | 5.8, 5.15, 6.1, 6.18 (latest): Sensor tests job `kernels` (Ubuntu runner, `os` all or ubuntu) boots each Ubuntu mainline build with virtme-ng 1.42 (`pipx`, `vng -r <version> --user root --network user`) under KVM (udev rule makes `/dev/kvm` usable); the guest shares the runner's filesystem copy-on-write, so the test binaries built on the runner run there through `scripts/ci/kernel-check.sh` (eBPF and pcap conformance, the keeper test alone); a kernel without BTF gets a warning and the pcap test only (decided 2026-11-25 over lvh, whose Debian images would need binaries built for them). Guest options: `--disable-microvm` (5.15 and 6.18 hang at ACPI set-up on microvm), 5.8 also `--force-9p --append psi=0` (no virtiofs root; 5.8.0 oopses in `psi_trigger_create` under current udev); `vng -v`, 10-minute `timeout` per guest | Implemented; green 2026-11-25 (run `45712541202`) |
| Coverage targets | ≥ 80% for `core`, `enrich`, `storage-*`, policy engine; ≥ 60% overall | Proposed |
| Test tags and layout | Smoke, integration, scenario: binaries of the `scribe-tests` crate (`tests/smoke`, `tests/integration`, `tests/scenario`, helpers in `tests/support`, `scribed-under-test` / `scribe-under-test` bins); functional: `crates/<crate>/tests/functional/`; unit tests in `src/` only for private code, under `mod functional`. `scripts/check-test-tags.sh` (nextest list) requires exactly one tag per test; smoke changes nothing outside its temp dir, live smoke is read-only | Decided |
| Test runner | `cargo-nextest`, process per test; `.config/nextest.toml`: warn 2 s / kill 6 s, integration and scenario warn 5 s / kill 10 s; profile `ci` writes JUnit | Decided |
| Isolation | Own temp dir, ports (`:0`), `FakeClock`, Postgres schema per test; no `set_var`, no global panic hook swaps (thread-local quiet hook in the module suite) | Decided |
| Fast run budget | Planned ≤ 60 s, hard limit 120 s (100% contingency) after the build; the Tests workflow fails over 120 s; 0.6 s today (183 tests) | Decided |
| CI time budgets | every-PR stage < 15 min, nightly-equivalent < 2 h, pre-release 1–2 days | Proposed |
| Release exit criteria | all scenarios and sensor conformance pass on every OS; no open crash / data-loss bugs; 7 crash-free fuzz runs in a row | Proposed |

**Test data conventions** (decided):
- Addresses only from documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`; client `10.0.0.2` / `fd00::2`.
- Names under `example.com` / `example.net`, no exceptions: the DoH resolver is `doh.example.net` at `198.51.100.53`, on a resolver list the test configures.
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
| Total size | ~18,000 production LOC + ~5,400 test LOC |
| Total effort | 123–153.5 person-days; 74–92.5 remaining after phases 0, 0b and 1–5, 89–111 with a 20% buffer (includes the security design, +14.5 days, the module framework, +10–12 days, and the 2026-11-22 plan review, +3.5–4.5) |
| Milestones (planned) | M1 MVP (phases 0, 0b, 1–6, 10, 11: pcap, SQLite, modes, CLI with `scribe daemon`, API access control, modules with URL) 67–82.5 days planned, 20.5–24 remaining; M2 native sensors 35.5–45.5 days; M3 production 20.5–25.5 days |
| Main risks | Apple notarization lead time (the Network Extension entitlement only if option 9A is picked); eBPF kernel variance; Npcap needed for Windows payloads; DoH / ECH hide hostnames; caution-mode tuning; Release workflow not run on GitHub yet (Tests green on all three systems since 2026-11-23) |
| Secrets | `scribe-secrets`: references `file:` (implemented: absolute path, Unix mode `0600` or stricter, owner = service account or root, no group/other-writable parent without sticky bit; created via temp file + hard link so a concurrent start keeps the first key; one trailing newline dropped), `keychain:<service>/<account>` (macOS generic password via `security-framework`; root sees the System keychain), `dpapi:<path>` (Windows: file holding a `CryptProtectData` blob, machine scope, UI forbidden), `secret-service:<label>` (Linux: `secret-service` 6 with `crypto-rust`, DH-encrypted session, attributes `application = scribe`, `scribe-secret = <label>`, default collection; needs a session bus and an unlocked keyring) — implemented in phase 11, each only on its own system (`Unsupported` elsewhere); `store()` writes any of them (`file:` via temp file + rename, `0600`), `read_or_create` creates in any of them; Windows `file:` ACL checks with the installer in phase 13. `Secret` hides its bytes in `Debug` and zeroes them on drop. Modules get `ModuleContext::data_dir` for their files | Implemented (file; OS stores phase 11 step 4: DPAPI tested on every Windows run, keychain round trip only with `SCRIBE_TEST_KEYCHAIN=1`, Secret Service only checked for a missing bus) |

## 15. Development environment

- Local cross-target checks (clippy for Linux / Windows from macOS) leave out the `sqlite` feature: bundled SQLite needs a C cross compiler. CI builds it natively on each OS.

| Item | Value |
|---|---|
| Editor | VSCodium with rust-analyzer (Testing panel on), CodeLLDB, Even Better TOML, YAML, GitHub Actions, ShellCheck, PowerShell (all from Open VSX) |
| Tracked editor files | `.vscode/settings.json`, `launch.json`, `tasks.json`, `extensions.json` only |
| Local CI equivalent | Task "ci: Tests workflow (local)" |
| Local build scripts | `scripts/build/{macos.sh, linux.sh, windows.ps1}` with shared `config` and `common.sh`; commands `doctor`, `build`, `test`, `check`, `release`, `clean` (+ `image`, `shell` on Linux, `service-test` on Windows); `dist/` archives and `SHA256SUMS` as `release.yml` makes them; `macos.sh` reads Xcode's `ACTION`, `CONFIGURATION`, `ARCHS` and writes universal binaries to `BUILT_PRODUCTS_DIR`; `linux.sh` runs itself with `--native` inside a native `arm64` image (`linux.Containerfile`) and cross-compiles `x86_64`; `windows.ps1` for PowerShell 7 and 5.1; `dist/` is git-ignored | Implemented (Windows not run on Windows yet) |
| Rosetta | Never required by a build or test step: general Rosetta ends after macOS 27; Rosetta for Linux VMs is reported to stay but unconfirmed (plan risk 10) | Decided |
| Coverage locally | rustup `llvm-tools` + `-C instrument-coverage` (no `cargo-llvm-cov` installed) |
