# Implementation plan for scribe

*Last updated 2026-11-24, after phase 11 (commits `2f6cf0e`…`44f0c44`, milestone M1) with options for the phases still stubbed (section *Options for the stubbed phases*); before that after phase 10 (`920c906`…`e78c339`), phase 6 (commits `f42a76b`…`b9a61ae`), phase 5 (commits `39796b2`…`173e2bf`), phase 4 (commits `9c36205`…`ef17bee`), phase 3 (commits `5a2ce1b`…`568ccb9`), phase 2 (commits `6122243`…`d24cfef`), phase 1 (commit `4216ebc`) and a plan review: secrets crate added to phase 3, phase 2 and 4 scope completed, CI risk and pending decisions added. Progress details: [status.md](status.md).
Decisions and config values: [scribe-conventions skill](../.claude/skills/scribe-conventions/SKILL.md).*

**Assumptions**
- One experienced Rust developer.
- "LOC" means Rust source lines without blanks and comments, except where another language is named.
- Tests are counted separately.
- Effort is in person-days of focused work and doesn't include waiting on Apple or code-signing vendors.

## Progress so far

- **Product code:** phases 0, 0b, 1–6, 10 and 11 done (milestone M1); see [status.md](status.md). `scribed` captures with the pcap sensor on every system, enriches flows (SNI, `Host`, DNS, QUIC), runs the URL module and the policy, stores hosts, counters (per process and per hour), baselines, alerts and audit records on SQLite, and is controlled through the local API: every `scribe` command works, including `scribe daemon …`. Alerts reach the log, signed webhooks and desktop notifications (`scribe notify`); threat lists download with integrity checks; secrets can live in the OS key stores. Native sensors (phases 7–9), Postgres (12) and installers (13) remain. Automated tests cover 91.0% of product code.
- **Test infrastructure (done):** test doubles (including module doubles), packet builders and fixture generator, storage, sensor and module conformance suites, 14 pcap fixtures with expected results, 19 daemon scenarios, draft raw sensor records, v1 and v2 schema snapshots, fuzz targets, UI mock data, end-to-end scripts. This was not a separate phase in the original plan; it front-loads most of the test work of phases 1–6.
- **Design (done):** [specs.md](specs.md) with use cases and requirements, the v1 config draft [config/scribe.toml](../config/scribe.toml) holding every default, and answers to all open questions (paths, scoring, buffers and limits, URL privacy, crate layout, logging, minimum Rust version). Nothing blocks implementation.
- **CI, versioning and tooling:** tag-based versioning, 8 GitHub workflows (Release and Version tracking automatic, the rest manual), VSCodium launch and task configs, conventions skill and `CLAUDE.md`. The same checks run locally before every commit. Tests run #1 (`45074989995`, 2026-11-22) passed on Linux only; run #2 (`45198461612`, 2026-11-23) ran all three systems: Linux and macOS passed, Windows had 9 test-portability failures; run #3 (`45202847881`, 2026-11-23) passed on all three, and run #4 (`45226370809`) after phase 10; after phase 11 run #5 (`45448523591`) failed on 7 Windows-only test assumptions and run #6 (`45452687480`) passed on all three. Release ran once for `v0.2.0` (`45322623374`); the other manual workflows have not run yet (risk 9).

## Phases

| # | Phase | Main work | Prod LOC | Test LOC | Planned (days) | Status | Remaining (days) |
|---|---|---|---|---|---|---|---|
| 0 | **Foundations** | Upgrade Rust; add tokio, serde, toml, tracing, thiserror, clap; config loading; logging; daemon startup and shutdown; first tests for untested crates; CI on Linux, macOS and Windows (Tests green on GitHub on all three since 2026-11-23, latest run `45226370809` after phase 10) | 400 | 50 | 2–3 | **Done** — dependencies, units, platform defaults, config loading and checks, logging, daemon startup and shutdown, CLI on `clap`, first tests for `core`, daemon, CLI and storage manager | 0 |
| 0b | **Module framework** | `crates/module-api` (`Module`, `FlowHook`, `Source`, manifest, context), `ModuleRegistry` in `scribed`, `[modules]` config with per-module sections, flow notes replacing `FlowEvent.url`, module records, metric samples and module state in `storage-api`, schema v2 snapshot and storage conformance cases, `crates/module-conformance`, `crates/module-url` skeleton, `privacy.url_query` → `[modules.url] query` alias (specs 7.4) | 1,100 | 500 | 8–10 | **Done** — module API, flow notes and observations, storage interface and schema v2, module conformance suite, URL module skeleton, `[modules]` config, `ModuleHost` in `scribed` | 0 |
| 1 | **SQLite backend** | rusqlite (bundled), migration runner, every StateStore and EventSink method, JSON payloads, WAL; must pass conformance | 900 | 250 | 4–5 | **Done** — rusqlite 0.43 (bundled), migration runner, every StateStore and EventSink method, shared JSON row codec, both conformance suites, snapshot migrations | 0 |
| 2 | **Storage manager** | Per-sink async writer tasks, batching, LRU cache, in-memory buffer for state-store outages, spool and replay, retention, health checks. Also: a retention call on `EventSink` (interface change, conformance case, SQLite and Postgres), SQLite calls moved off the async runtime (blocking thread or a worker per backend), the stopgap one-second module-output drain in `serve()` replaced by the writer tasks, and the storage tests still missing (`proptest` counter properties, many writers on one host and on one SQLite file, in-memory SQLite) | 950 | 500 | 6.5–7.5 | **Done** — retention call on `EventSink`, SQLite worker thread, writer task per sink (batching, non-blocking publish, retention), spool and replay, state-store outage buffer, host and baseline cache, storage health, the missing storage tests | 0 |
| 3 | **Enrichment** | DNS answer parser and IP-to-host cache, TLS ClientHello SNI, HTTP request and URL parsing with redaction (`[modules.url] query`), QUIC Initial decryption for SNI (`ring` 0.17); parser tests on recorded sample traffic. The HTTP request and URL parser is written in `crates/module-url` as the first module (specs 7.4.6); core enrichment keeps SNI, `Host`, DNS and QUIC. **Secrets crate** (new, needed first here): one interface over the macOS keychain, Windows DPAPI, Linux Secret Service and root-only `file:` references, used for the `hash` mode key and later by phases 11, 12 and 13 | 1,500 | 600 | 9–12 | **Done** — TLS ClientHello (SNI, ALPN, ECH), HTTP request heads, DNS answers and IP-to-name cache, `Enricher` (name order, security, ECH), QUIC v1 / v2 Initial decryption and reassembly, URL parser and all five `query` modes, `scribe-secrets` with `file:` references; 16 fixtures pass end to end; DNS and QUIC fuzz targets. OS secret stores moved to phase 11 | 0 |
| 4 | **Policy engine** | Learn / caution / alert modes, scoring rules (raw IP, unusual port, high-entropy names, new top-level domain, new process, threat list), alert dedupe and rate limits, automatic switch out of learn mode. Scores for module signals (`url.*` …): `[policy.scores]` gains a table for namespaced reasons, with config checks, the shipped `scribe.toml` and tests | 950 | 500 | 6.5–8.5 | **Done** — `scribe-policy`: signals, threat lists (files), `Policy::decide` with the mode table, scoring with module signals, learn timer, dedupe, acknowledgement, alert notes; `[policy.scores]` module keys; `scribed` builds the policy at start; scenario runner with 16 of 19 scenarios passing (3 need phase 5). Rate limits beyond dedupe moved to phase 11 | 0 |
| 5 | **Daemon pipeline** | Wire sensor → enrichment (a QUIC `InitialReassembler` per UDP flow, DNS responses into the cache) → policy (save baseline additions and alert state, load known processes, pause the learn timer while hibernating) → storage; per-host and per-process counters; run as a systemd, launchd or Windows service; drop privileges. Run states for `scribe daemon` (specs 8.5): runtime metrics registry and health checks, counter reset, cache flush, live config reload (also SIGHUP) with the live / needs-restart split, hibernate and wake up (sensor stop and start again, `--for` timer on `Clock`, `learn_for` paused, `audit` events). Security: StrictModes file-mode checks at start, `daemon.max_hibernate` cap and `hibernated` alert, `audit` events for stops, crashes and refused calls, sequence + `prev_hmac` chain on audit and alert records | 1,500 | 450 | 9.5–11.5 | **Done** — pipeline (enrichment, QUIC holding, DNS answers, modules, policy, writes), per-host and per-process counters (schema v3), `scribed` runs it with a sensor thread; run states (hibernate capped by `[daemon] max_hibernate`, wakeup, reset, status), config reload (SIGHUP) with the live / restart split, audit and alert chain, start / stop / unclean-stop audits, StrictModes, systemd notify, launchd plist, Windows service, `[daemon] user`; all 19 scenarios pass. Hourly buckets and restoring alert state at start moved to phase 10 | 0 |
| 6 | **pcap sensor** (fallback) | libpcap / Npcap capture of SYN, UDP, DNS and ClientHello packets; reassemble the first bytes of each flow. Per phase 0b: send `Observation`s with up to 4 KiB of client bytes and `Payload` observations for later requests on a connection, copy payload past the ClientHello / `Host` header only when an enabled module needs it, and pass the new *stop, then start again* sensor conformance case | 700 | 200 | 4–5 | **Done** — decoder (Ethernet / VLAN, loopback, raw IP, Linux cooked; IPv4, IPv6), pcap file reader and replay, flow tracker (first bytes reassembled, later HTTP requests, QUIC follow-ups, DNS responses, closes with bytes), live capture with libpcap / Npcap loaded at run time, `[sensor] interface`, fallback from the native sensors; passes the sensor conformance suite (with the new stop / start case) live on Linux; every fixture through replay and the pipeline | 0 |
| 7 | **Linux eBPF sensor** | aya probes on `tcp_connect` / `udp_sendmsg` and cgroup sockets, a socket filter for packet contents, ring-buffer reader, process lookup via `/proc`. Security: privileged part only loads and attaches, keeps only `CAP_BPF` / `CAP_PERFMON`, root-only pinned maps | 1,700 (Rust + eBPF) | 350 | 11.5–15.5 | **~2%** — stub, draft raw records | 11.5–15.5 |
| 8 | **Windows ETW sensor** | Kernel-Network and DNS-Client providers, process path lookup, Npcap for packet contents. Security: service SID, processing as `NT SERVICE\scribed` where ETW allows | 1,300 | 230 | 11–13 | **~2%** — stub, draft raw records | 11–13 |
| 9 | **macOS Network Extension** | Swift `NEFilterDataProvider` (~1,000 Swift), XPC bridge in Rust (~500), container app and installer. Security: code-signing requirement checked both ways on XPC, versioned schema with size limits, decoder fuzzed | 1,650 (Swift + Rust) | 200 | 13–17 | **0%** — draft XPC message format only | 13–17 |
| 10 | **Local API and CLI** | gRPC (tonic) over a Unix socket or named pipe, access control by socket permissions and caller identity (read vs control calls); CLI commands `status`, `hosts`, `mode`, `alerts`, `baseline add/rm`, `alerts ack`, `export`; `scribe daemon status` (with `--json`, `--watch`), `health` (also `grpc.health.v1`), `reset`, `hibernate [--for]`, `wakeup`. Security: socket in a `root:scribe` `0750` directory, named-pipe access list with `first_pipe_instance` / `reject_remote_clients`, OS identity in request extensions, clients check the server, message / timeout / stream limits, `export` streamed and written by the CLI. Modules: `ListModules`, `ModuleStatus`, per-module services, `scribe modules` and module subcommands, per-module section in `daemon status` | 2,000 | 700 | 12–13 | **Done** — `scribe-api` (protocol without `protoc`, Unix socket and Windows named pipe, caller identity, access policy, limits), read and control calls in `scribed` with audit events and `grpc.health.v1`, every CLI command incl. `scribe daemon`, `scribe modules`, `scribe audit verify`, per-module services (`scribe url list`); from phase 5: hourly counter buckets (schema v4), alert state restored at start, audit verification; `MockApiServer` and the UI mocks checked against the protocol | 0 |
| 11 | **Alert outputs** | OS notifications on each platform, structured log, webhook. Security: HTTPS only (loopback excepted), no cross-host redirects, HMAC-signed webhooks with the secret from the keychain, optional pinning; threat-list download with optional `sha256` / `minisign` check, last good list kept, entry cap. OS secret-store backends for `scribe-secrets` (macOS keychain, DPAPI, Secret Service; moved from phase 3), first needed by the webhook secret | 900 | 250 | 5.5–7 | **Done** — `scribe-alerts` (dispatcher with a queue and rate limit per output, log, signed webhook), `scribe-net` (HTTPS rules, pinning), `scribe notify` agent in the user's session (a system service can't reach the desktop) with login files, threat-list downloads with `sha256` / minisign / entry cap and last good copy, keychain / DPAPI / Secret Service and `scribed --set-secret` | 0 |
| 12 | **Postgres backend** | tokio-postgres with a deadpool connection pool, migrations, conformance tests against a Postgres container in CI. Security: TLS via `tokio-postgres-rustls`, default `verify-full`, `disable` / `prefer` rejected off loopback, optional client certificates; `INSERT`-only sink role, one role per host with row-level security; heartbeats | 1,100 | 250 | 5.5–6.5 | **~10%** — v1 and v2 migrations and seeds, stubs, CI job with Postgres 16; reuses the shared row codec from phase 1 | 5–6 |
| 13 | **Packaging and release** | `.deb` / `.rpm`, MSI (WiX, keeps config / data / logs next to the app across upgrades), macOS `.pkg` with notarization, signing, install and uninstall scripts. Security: hardened systemd unit, `scribe` / `scribe-admin` groups and file modes, signed `SHA256SUMS` and build provenance, signed `.deb` / `.rpm` repositories; optional `storage.encrypt` (SQLCipher, AES-256-GCM spool, key in the OS secret store) | 1,000 (scripts/config + Rust) | 150 | 9–11 | **~15%** — Release workflow builds archives for 4 targets with checksums; installers left | 8–10 |
| 14 | **Hardening** | Fuzz the packet parsers, performance and memory tests under load, security review, user docs. Security: `cargo deny` / `cargo audit` in Tests, Actions pinned by SHA with minimal `permissions:` (can be done any time), review against specs 12.1.1 | 500 | 300 | 6–8 | **~10%** — fuzz targets and workflow; never run | 5–7 |
| | **Total** | | **~18,000** | **~5,400** | **123–153.5** | **phases 0, 0b, 1–6, 10, 11 done** | **53.5–68.5** |

With a 20% buffer for unknowns, plan on **64–82 person-days remaining**. That's about 3–4 months for one developer, or under 2 months for two or three working in parallel.

## Milestones

| Milestone | Phases | Result | Planned | Remaining |
|---|---|---|---|---|
| **M1: MVP** | 0, 0b, 1–6, 10, 11 | Runs on all three OSes using pcap (no process attribution), SQLite storage, all three modes, CLI including `scribe daemon`, notifications, local API access control, module framework with the URL module | 67–82.5 days | **Done** (2026-11-24); Tests green on all three systems (run `45452687480`) |
| **M2: Native sensors** | 7, 8, 9 | Process attribution and better hostname coverage on each OS; privilege split, XPC code signing | 35.5–45.5 days | 35.5–45.5 days |
| **M3: Production** | 12, 13, 14 | Postgres over TLS, signed installers and checksums, fuzzed parsers, security review | 20.5–25.5 days | 18–23 days |

**Parallel work:** after M1, the three native sensors (phases 7, 8 and 9) don't depend on each other, so they can go to different developers. Postgres (phase 12) can be done any time after phase 2.

## Next steps

In this order, because each one turns existing tests and data into real coverage:

0. **Tag a release for M1:** Tests passed on all three systems after phase 11 (run `45452687480`, commit `44f0c44`; the first run, `45448523591`, found 7 Windows-only test problems, fixed in `44f0c44`).
1. **Apply for Apple's Network Extension entitlement now**, so the wait overlaps M2 (risk 1). Listed since October; not done yet as far as this plan knows.
2. **Choose the approach for each stubbed phase** (section *Options for the stubbed phases* below); the recommended order starts with process attribution on all three systems from socket tables (option P), then the native sensors.
3. **M2: native sensors** (phases 7–9, independent of each other) for process attribution; Postgres (phase 12) any time.
4. **Any time, cheap:** add `cargo deny` / `cargo audit` to the Tests workflow and pin Actions by SHA (phase 14 work that needs no product code).

## Options for the stubbed phases

*Added 2026-11-24, after M1.* Phases 7, 8, 9 and 12 are stubs (a crate that compiles and reports
`unavailable`, or migrations only); 13 and 14 are partly scripted. For each, the realistic ways to
build it, what they cost and what they give. Days are focused person-days like the phase table; the
plan's estimates are for the option marked **plan**. Nothing here is decided until you pick.

### P. Cross-cutting first step: process attribution from socket tables (new option)

**Status: implemented 2026-11-24** (`crates/process`, `[sensor] process_lookup = true`): tests find
the test process's own sockets through the real table on Linux, macOS and Windows (Tests run
`45521781418`, after `45520007761` timed out once on an older SQLite test, fixed in `23d27b7`). Took about a day, well under the 6–8 days estimated,
because one shared `Resolver` and sensor wrapper serve all three tables.

Every native sensor exists mainly for **process attribution**, which the pcap fallback lacks (UC-6).
A cheaper route gives most of it on all three systems now, without kernel programs, drivers or
Apple's entitlement: keep the pcap sensor for packets and names, and look up the owning process of
each new flow in the OS socket table by its 5-tuple.

| System | Source of the socket → process mapping |
|---|---|
| Linux | `NETLINK_SOCK_DIAG` (socket inode for the 5-tuple) and `/proc/<pid>/fd` → path from `/proc/<pid>/exe` |
| Windows | `GetExtendedTcpTable` / `GetExtendedUdpTable` with `OWNER_PID`, then `QueryFullProcessImageNameW` |
| macOS | `libproc`: `proc_listpids` and `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` per process, cached and refreshed on a miss |

- **Gives:** process path and pid on most flows everywhere; one `ProcessResolver` interface in
  `core`, three small implementations, the sensor conformance suite extended with a process case.
- **Misses:** very short-lived connections (the socket is gone before the lookup) and UDP sockets
  that send once; it reads other processes' tables, so it needs root / Administrator like capture.
- **Cost:** 6–8 days for all three, no new risks. It stays useful afterwards as the attribution
  for the pcap fallback (old kernels, no Npcap ETW rights, no approved extension).
- **Recommendation:** do this first. It turns M2's main promise into something users get within
  about a week and lowers the urgency of the three native sensors.

### Phase 7: Linux sensor

| Option | How | Gives | Costs and risks | Days |
|---|---|---|---|---|
| **7A eBPF with `aya`** (plan) | Rust eBPF programs on `tcp_connect` / `udp_sendmsg` / cgroup socket hooks, ring buffer, CO-RE via BTF | Every connection with pid, cgroup and the first bytes, no polling races; one language | eBPF programs need nightly Rust and `bpf-linker` to build (kept in a separate crate built by `xtask` / CI, the object embedded); `aya` raises the minimum Rust to 1.98 (risk 8); kernel 5.8+ | 11.5–15.5 |
| 7B eBPF with `libbpf-rs` | Programs in C (`clang -target bpf`, `vmlinux.h`), loaded through libbpf (vendored C) | Most mature loader and verifier coverage across kernels | C toolchain and libbpf / libelf in every Linux build; two languages to review | 12–16 |
| 7C No kernel programs | Option P on Linux plus `NETLINK_CONNECTOR` process events and conntrack events (`nfnetlink`) for short-lived flows | Works on any kernel, no eBPF privileges, simple to review | Short flows still racy without conntrack; conntrack needs the module loaded and `CAP_NET_ADMIN` | 5–7 (on top of P: 2–3) |

**Recommendation:** P now, then **7A** with the eBPF object built in CI and checked into the
release, so day-to-day builds stay on stable Rust. 7B only if `aya` turns out not to load on a
kernel you must support.

### Phase 8: Windows sensor

| Option | How | Gives | Costs and risks | Days |
|---|---|---|---|---|
| **8A ETW + Npcap** (plan) | Real-time ETW session on `Microsoft-Windows-Kernel-Network` and `Microsoft-Windows-DNS-Client` (through `windows-sys` or the `ferrisetw` crate); packet contents from the existing pcap sensor joined by 5-tuple | Every connection with pid and the DNS names Windows resolved; SNI and URLs still from Npcap | Kernel-Network events need Administrator / a service with the right privilege; joining two event streams by 5-tuple and time; ETW buffer loss under load must be counted | 11–13 |
| 8B Socket table only | Option P on Windows (IP Helper tables) and Npcap | Process for most flows, almost no new code | Misses short-lived flows; no DNS-client names (pcap DNS still works) | 2–3 (part of P) |
| 8C WFP callout driver or WinDivert | Kernel filter with flow and payload | Exact attribution and payload in one place; the path to blocking later | Needs an EV code-signing certificate and driver review; WinDivert's driver is third-party code in the kernel | 20+ and vendor waits |

**Recommendation:** P (that is 8B) now, then **8A**. 8C only with the later blocking feature.

### Phase 9: macOS sensor

| Option | How | Gives | Costs and risks | Days |
|---|---|---|---|---|
| **9A Network Extension** (plan) | Swift System Extension with `NEFilterDataProvider`, XPC to `scribed`, container app, notarized `.pkg` | Every flow with the app's audit token and signing identity, the remote host name the app asked for, the first bytes; the only Apple-supported way | Apple Developer Program, the content-filter entitlement (weeks of waiting, risk 1), notarization, user or MDM approval; Swift and XPC code to secure (risk 7) | 13–17 + waits |
| 9B `libproc` socket table | Option P on macOS (`proc_pidfdinfo`), with the existing pcap sensor | Process path for most flows, no entitlement, works today | Races for short flows; polling cost grows with the number of processes; no per-app signing identity | 2–3 (part of P) |
| 9C Private `NetworkStatistics` framework (what `nettop` uses) | Undocumented API | Every flow with process, no entitlement | Private API can break with any macOS update and blocks notarized distribution through some channels; not recommended | 5–7 |

**Recommendation:** P (9B) now; **apply for the entitlement today** and build 9A when it arrives.

### Phase 12: Postgres backend

| Option | How | Gives | Costs and risks | Days |
|---|---|---|---|---|
| **12A `tokio-postgres` + `deadpool-postgres` + `tokio-postgres-rustls`** (plan) | Hand-written queries through the shared row codec, existing migrations | Fits the async storage manager; TLS on rustls like `scribe-net`; small dependency set | Queries checked only by the conformance suite (which already exists) | 5.5–6.5 |
| 12B `sqlx` (Postgres, rustls) | Compile-time checked queries, its migration runner | Query typos caught at build time | Needs a database or the `.sqlx` offline data at build time; heavier; its migrator would replace the existing one | 6–7 |
| 12C Event sink first, state store later | 12A for `EventSink` only (UC-9, the fleet history), Postgres as state store afterwards | The fleet use case in about half the time | Two steps; config rejects Postgres as state store until step two | 3 + 3 |

**Recommendation:** **12A, delivered as 12C** (sink first): UC-9 is what people ask Postgres for.

### Phase 13: packaging and release

| Choice | Options | Recommendation |
|---|---|---|
| Linux packages | `cargo-deb` + `cargo-generate-rpm` (read `Cargo.toml`, Rust tools); or `nfpm` (one YAML for `.deb`, `.rpm`, `.apk`) | `nfpm`: one file for both formats and the same systemd unit and scriptlets |
| Windows installer | WiX v5 through `cargo-wix`; or MSIX | WiX: MSIX can't install a classic service with files next to the app (specs 9.1) |
| macOS package | `pkgbuild` / `productbuild` + `notarytool`; the extension (9A) joins later | As planned; the `.pkg` can ship before 9A with the daemon, CLI and the `scribe notify` agent |
| Release signing (open question 13) | cosign keyless (GitHub OIDC, Rekor log); or minisign (a key you keep; offline checks; scribe already verifies minisign for threat lists) | minisign-signed `SHA256SUMS` plus GitHub build-provenance attestations: no online service needed to verify, same tool as threat lists |
| Encryption at rest | SQLCipher + AES-GCM spool (plan); or leave it to full-disk encryption | Keep it optional and last; can slip past v1 (risk 7) |

### Phase 14: hardening

| Choice | Options | Recommendation |
|---|---|---|
| Fuzzing | Scheduled nightly `cargo fuzz` in CI (the Fuzz workflow exists, never run); or OSS-Fuzz | Run the existing workflow weekly on a schedule; OSS-Fuzz only once the project is public and stable |
| Supply chain | `cargo deny` + `cargo audit` in Tests, Actions pinned by SHA, minimal `permissions:` | Do now; it needs no product code |
| Performance | Criterion benchmarks for the parsers and pipeline; a load test replaying fixtures at high rate with memory limits from NFRs | Replay-based load test first: it checks the < 100 MB memory target directly |

### UI (after M3)

Tauri on the existing local API and mock data (planned), or a terminal UI (`ratatui`) first: a TUI
needs no installers or code signing of its own and reuses the CLI client, so it can ship with M2.

### Suggested order

1. ~~**P**~~ done 2026-11-24: process attribution on all three systems.
2. **Tag the M1 release**, and send the Network Extension entitlement request (no code).
3. **12C** sink (3 days) and the cheap part of 14 (supply chain, scheduled fuzzing; 1 day).
4. **7A** and **8A** (in parallel if two people), then **9A** when Apple approves.
5. **13** installers, then the rest of 12 and 14.

P adds 6–8 days to M2 (8B and 9B are part of it, not extra), so M2 becomes 41.5–53.5 days if all
of 7A, 8A and 9A still follow. What P buys is that process attribution arrives in the first week
instead of at the end of M2, and that each native sensor can then be judged on what it adds over P.

## Decisions since the first version

| Decision | Effect on the plan |
|---|---|
| Storage backends limited to SQLite and Postgres | ClickHouse, OpenSearch, file sinks and external gRPC storage plugins dropped |
| `ring` 0.17 for QUIC Initial decryption | Phase 3 adds a C-compiled dependency; fixture checked against RFC 9001 Appendix A |
| Minimum Rust version follows the dependencies: 1.89 now, 1.98 expected in phase 7 (aya) | No crates pinned to old releases; each raise lands with the dependency that needs it (was risk 6) |
| All test workflows manual, only Release and Version tracking automatic | The test approach's "nightly" stage is run by hand |
| Versions come from `v*` git tags | Release work in phase 13 is down to installers and signing |
| Default paths: OS defaults on Linux / macOS, logs in `/var/log/scribe/`; on Windows config, data and log file next to the app, logs to the Event Viewer when configured (`log.output`) | Phase 0 config and logging, phase 13 installers create these folders |
| Draft v1 config `config/scribe.toml` holds every default (policy scores, cache, buffer, spool, logging) | Phase 0 loads it; phases 2 and 4 implement the limits and scores it defines |
| State store outage: in-memory buffer, oldest dropped on overflow | Phase 2 adds the buffer next to the on-disk sink spool |
| New crates (option A): `crates/policy`, `crates/alerts`, `crates/api` + `proto/scribe/v1/api.proto` | Phases 4, 11 and 10 each start by creating their crate; the CLI uses only the API client |
| `scribe daemon` subcommands: `status`, `health`, `reset`, `hibernate`, `wakeup` (specs 6.2.1, 8.5) | Phase 5 +350 LOC / +2 days for run states, metrics, reload and hibernation; phase 10 +300 LOC / +1.5 days for the API calls and commands; every sensor must stop and start again (new sensor conformance case). M1 +3.5 days |
| Module framework (specs 7.4, implemented in phase 0b): features as compiled-in modules with generic outputs (flow notes, module records, metric samples, module state); URL tracking becomes the first module; kernel metrics is the example of a later one | New phase 0b (8–10 days) before phase 1; phase 10 +2 days for module API and CLI plumbing; schema v2 before SQLite; `privacy.url_query` becomes `[modules.url] query`. M1 +10–12 days |
| Security design for every interaction (specs 12.1.1, NFR-17 – NFR-19; all Proposed) | +2,000 LOC, +730 test LOC, +14.5 days, following the spec's suggested order: phase 5 +1.5 (StrictModes, hibernate cap, audit chain), 7 +1.5, 8 +1, 9 +1 (privilege split, XPC signing), 10 +2 (API access and limits), 11 +1.5 (HTTPS, signed webhooks, threat-list checks), 12 +2 (Postgres TLS, roles, heartbeats), 13 +3 (service hardening, release signing, optional encryption at rest), 14 +1 (`cargo deny` / `audit`, pinned Actions, review). M1 +5 days, M2 +3.5, M3 +6 |
| SQLite through `rusqlite` 0.43 with bundled SQLite (phase 1) | No system SQLite needed on any OS; local Linux / Windows compile checks from macOS leave the `sqlite` feature out (it needs a C cross compiler), so only CI builds it there |
| SQLite calls run synchronously behind a mutex (phase 1) | Resolved in phase 2: each database runs on its own worker thread |
| Plan review 2026-11-22 | Secrets crate in phase 3 (+2–3 days), retention call, async SQLite and missing storage tests in phase 2 (+1.5), module signal scores in phase 4 (+0.5), shared codec saves 0.5 in phase 12; "rare host" removed from phase 4 (it is in neither the spec nor the config). Remaining +3.5–4.5 days, M1 +4–5 |
| Phase 11 done 2026-11-24 | OS notifications come from a `scribe notify` agent in the user's session (a system service can't post to a desktop on any of the three systems), with login files in `packaging/`; outgoing HTTPS through a small own client (`scribe-net`) because no maintained client lets a caller pin a certificate; the webhook sits behind a `scribe-alerts` feature so the CLI stays free of ring's C code. Remaining −5.5–7 days, M1 done |
| Phase 10 done 2026-11-23 | Took in the phase 5 leftovers (hourly buckets as schema v4, alert state at start, `scribe audit verify`); protocol built with `protox`, so no `protoc` on any build machine; the Windows named pipe is compiled locally but only exercised by the Windows CI runner; group creation (`scribe`, `scribe-admin`) stays with the installers (phase 13). Remaining −11.5–12.5 days, M1 −11.5–12.5 |
| Phase 6 done 2026-11-22 | libpcap / Npcap loaded at run time instead of linked (no SDK at build time, `scribed` keeps running without it); the pcap sensor is also the Linux and Windows fallback now. The local build scripts (about a day, outside the phase totals) came first. Remaining −3.5–4.5 days, M1 −3.5–4.5 |
| Phase 5 done 2026-11-22 | Hourly counter buckets (FR-9) and restoring alert state at start (with acknowledgements) moved to phase 10 (+0.5 day); storage limits, sink and log-format changes need a restart for now; heartbeats stay in phase 12. Remaining −9.5–11.5 +0.5 days, M1 −9 to −11 |
| Phase 4 done 2026-11-22 | Alert rate limits beyond the per-host dedupe moved to phase 11 (outputs throttle, no change in days); saving policy state and pausing the learn timer belong to the pipeline (phase 5, already in its estimate). Remaining −5.5–7.5 days, M1 −5.5–7.5 |
| Phase 3 done 2026-11-22 | OS secret-store backends moved to phase 11 (+1–1.5 days; phase 3 ships `file:` references, which the default URL `hash` key uses); joining QUIC ClientHellos split over several datagrams needs per-flow state, so the pipeline (phase 5) keeps the reassembler (no change in days). Remaining −8–11 +1–1.5 days, M1 −7–9.5 |
| Storage manager timers use the runtime's monotonic clock (phase 2) | Batching and retry waits use Tokio time (tested with paused time); wall-clock values (retention cutoffs, stored times) still come from `Clock` |

## Decisions needed before a phase

Open questions from [specs.md](specs.md) section 15 that a phase can't finish without:

| Question | Needed by | Proposed answer |
|---|---|---|
| 9. Does hibernation survive a restart? | Phase 5 | No; a restart always resumes processing |
| 11. Default for `daemon.max_hibernate`, and may it be unlimited? | Phase 5 | Answered: `4h`; `""` = unlimited, warned at every start |
| 12. Group names `scribe` / `scribe-admin`, created by whom? | Phase 10 (checks), 13 (installers) | These names, created by the installers |
| 15. How long `privacy.url_query` stays an alias | Release after phase 3 | One minor version, with a warning |
| 13. Release signing: cosign keyless or minisign | Phase 13 | Open |
| Keep `x86_64-apple-darwin` as a release target? Intel Macs stop at macOS 26 and Rosetta ends after macOS 27 (risk 10) | Phase 13, or the next release | Keep building it (cross-compiling needs no Rosetta) while macOS 26 is supported; test it only on an Intel Mac or in CI; drop it when CI loses Intel macOS runners |

## Risks

1. **Apple's Network Extension entitlement and notarization:** approval can take weeks of waiting on top of the work. Apply during M1.
2. **eBPF across kernel versions:** use CO-RE (compile once, run everywhere) and keep pcap as the fallback for kernels older than 5.8.
3. **Windows packet contents:** ETW gives flows but not payloads, so SNI needs Npcap. A WFP driver would remove that dependency but requires EV signing; leave it for a later blocking feature.
4. **Hostname visibility:** DNS-over-HTTPS and Encrypted Client Hello hide hostnames. Detect and report these flows as "unresolved" rather than dropping them.
5. **Alert fatigue:** caution mode's scoring will need tuning on real traffic. Plan for a round of adjustments after M1.
6. **Module framework scope:** a general interface designed with only one real module risks fitting URL tracking alone. A test-only metrics source module (`TicksModule`) already exercises the interface without a flow hook; keep the outputs generic and mark `scribe-module-api` unstable until a second real module exists.
7. **Security scope (new):** the 12.1.1 design touches every phase and three OSes. The privilege split and the API access checks are the riskiest parts: keep the privileged code tiny, test every control call as a read-only peer, and review both in phase 14. Encryption at rest (`storage.encrypt`) is optional and can slip past v1 without blocking a release.
8. **Minimum Rust version (resolved):** policy *follow dependencies*, 1.89 now. Remaining risk: a dependency may require a very recent Rust (aya 0.16 needs 1.98); that's accepted, since release binaries are built on current stable.
9. **CI partly run:** Tests run #2 (`45198461612`, 2026-11-23): the whole workspace, including the crates with C code (bundled SQLite, `ring`), builds on Linux, macOS and Windows and passes on Linux and macOS; 9 Windows tests failed on Unix-only paths and TOML escapes; after the fix, run #3 (`45202847881`) passed on all three, and run #4 (`45226370809`, after phase 10) too, with the Windows named pipe and Postgres migrations 1–4. Version tracking has run (`45072299330`, once cited here as Tests by mistake). Release passed for `v0.2.0` (`45322623374`, 4 archives and `SHA256SUMS`); after phase 11, run #5 (`45448523591`) failed on 7 Windows-only test assumptions and run #6 (`45452687480`) passed on all three. Sensors, E2E, Fuzz and UI have not run there yet.

10. **Rosetta retirement (new, 2026-11-22):** macOS 27 is the last release with general-purpose Rosetta; from macOS 28 (autumn 2027) Apple keeps it only for older unmaintained games ([Apple](https://support.apple.com/en-us/102527)). Rosetta for Linux VMs (used by Apple `container` for `amd64` images) is reported to continue, but Apple's support page doesn't say so. So no build or test step may *depend* on Rosetta: Linux release builds cross-compile from a native `arm64` container, `x86_64` Linux tests run natively (WSL2 on the Windows x64 machine, or CI), and `x86_64` macOS tests run in CI. Rosetta stays an optional shortcut while it works.

## Local build scripts (implemented 2026-11-22)

One script per host, the same commands everywhere (`doctor`, `build`, `test`, `check`, `release`, `clean`), versions in one shared file (`scripts/build/config`), and `dist/` archives named exactly as `release.yml` names them, so CI can call the same scripts.

| Host | Script | Builds | Tests |
|---|---|---|---|
| macOS (Apple silicon), Terminal or Xcode | `scripts/build/macos.sh` | `aarch64-apple-darwin` natively; `x86_64-apple-darwin` by cross-compiling (no Rosetta); universal binary with `lipo` | `arm64` natively; `x86_64` in CI. Inside Xcode: reads `CONFIGURATION`, `ARCHS`, `ACTION`, writes to `BUILT_PRODUCTS_DIR`, puts `~/.cargo/bin` on `PATH`, prints Xcode-style errors; an External Build System target now, a Run Script phase for the Network Extension in phase 9 |
| macOS → Linux | `scripts/build/linux.sh` with Apple `container` (falls back to docker / podman) | Native `arm64` Ubuntu container; `x86_64-unknown-linux-gnu` cross-compiled in it (`gcc-x86-64-linux-gnu` or cargo-zigbuild, glibc pinned to the base image or older) | `aarch64` Linux tests in the container; `--arch amd64` under Rosetta only as an optional extra while it exists |
| Windows x64 | `scripts/build/windows.ps1` (PowerShell 7, works on 5.1) | `x86_64-pc-windows-msvc` natively (MSVC Build Tools, Windows SDK; Npcap SDK from phase 6, WiX from phase 13) | Natively, admin for service and sensor tests |
| Windows x64 → Linux | `scripts/build/linux.sh --native` in WSL2 Ubuntu | `x86_64-unknown-linux-gnu` natively | `x86_64` Linux tests natively; WSL2's kernel also suits the eBPF work of phase 7 |
| CI | the same scripts | every release target | every target |

Status: `scripts/build/{config, common.sh, macos.sh, linux.sh, linux.Containerfile, windows.ps1}` exist.
Verified here: `macos.sh doctor / check / release / xcode` (universal binary from a minimal Xcode-like environment);
`linux.sh image / doctor / check / test / release --all-targets` with Apple `container` (native arm64 image, x86_64
cross-compiled, binaries need glibc 2.34; 359 tests pass on Linux). `windows.ps1` parses in PowerShell 7.4 and its
`doctor` runs; it has not run on Windows yet. Not verified: `linux.sh` with docker or podman, and in WSL2. CI doesn't
call the scripts yet.

## Not included
- **Tauri UI:** about 4–6k LOC (TypeScript + Rust), 20–30 days. Test folders and mock API data already exist.
- **Blocking connections:** nftables, Network Extension verdicts, WFP; about 15–20 days.
- **Opt-in MITM module for full URLs inside TLS:** about 15 days; would be a module (specs 7.4).
- **Kernel metrics module (`kperf`):** TCP retransmits, RTT, run-queue delay via eBPF / ETW / `sysctl`; about 8–12 days after phase 0b and the native sensors (specs 7.4.8).
