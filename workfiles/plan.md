# Implementation plan for scribe

*Last updated 2026-11-08, after phase 0 (commit `dcb99ea` plus the docs commit); `scribe daemon` subcommands added to phases 5 and 10; security design (specs 12.1.1) spread over phases 5–14; module framework (specs 7.4) added as phase 0b, now done. Progress details: [status.md](status.md).
Decisions and config values: [scribe-conventions skill](../.claude/skills/scribe-conventions/SKILL.md).*

**Assumptions**
- One experienced Rust developer.
- "LOC" means Rust source lines without blanks and comments, except where another language is named.
- Tests are counted separately.
- Effort is in person-days of focused work and doesn't include waiting on Apple or code-signing vendors.

## Progress so far

- **Product code:** phases 0 and 0b done. The module framework runs in `scribed` with the URL module skeleton; see [status.md](status.md).
  Phase 0: `scribed` loads and checks the full v1 config, logs, opens storage and runs until stopped; the CLI parses every command. Nothing captures, stores or alerts yet. Automated tests cover 89% of product code (97% of `core`, 95% of the daemon, 99% of the module API).
- **Test infrastructure (done):** test doubles, packet builders and fixture generator, storage and sensor conformance suites, 13 pcap fixtures with expected results, 11 daemon scenarios, draft raw sensor records, v1 schema snapshots, fuzz targets, UI mock data, end-to-end scripts. This was not a separate phase in the original plan; it front-loads most of the test work of phases 1–6.
- **Design (done):** [specs.md](specs.md) with use cases and requirements, the v1 config draft [config/scribe.toml](../config/scribe.toml) holding every default, and answers to all open questions (paths, scoring, buffers and limits, URL privacy, crate layout, logging, minimum Rust version). Nothing blocks implementation.
- **CI, versioning and tooling (done):** tag-based versioning, 8 GitHub workflows (Release and Version tracking automatic, the rest manual), VSCodium launch and task configs, conventions skill and `CLAUDE.md`.

## Phases

| # | Phase | Main work | Prod LOC | Test LOC | Planned (days) | Status | Remaining (days) |
|---|---|---|---|---|---|---|---|
| 0 | **Foundations** | Upgrade Rust; add tokio, serde, toml, tracing, thiserror, clap; config loading; logging; daemon startup and shutdown; first tests for untested crates; CI on Linux, macOS and Windows | 400 | 50 | 2–3 | **Done** — dependencies, units, platform defaults, config loading and checks, logging, daemon startup and shutdown, CLI on `clap`, first tests for `core`, daemon, CLI and storage manager | 0 |
| 0b | **Module framework** | `crates/module-api` (`Module`, `FlowHook`, `Source`, manifest, context), `ModuleRegistry` in `scribed`, `[modules]` config with per-module sections, flow notes replacing `FlowEvent.url`, module records, metric samples and module state in `storage-api`, schema v2 snapshot and storage conformance cases, `crates/module-conformance`, `crates/module-url` skeleton, `privacy.url_query` → `[modules.url] query` alias (specs 7.4) | 1,100 | 500 | 8–10 | **Done** — module API, flow notes and observations, storage interface and schema v2, module conformance suite, URL module skeleton, `[modules]` config, `ModuleHost` in `scribed` | 0 |
| 1 | **SQLite backend** | rusqlite (bundled), migration runner, every StateStore and EventSink method, JSON payloads, WAL; must pass conformance | 900 | 250 | 4–5 | **~15%** — v1 and v2 schemas and snapshots, stubs; conformance tests (now with module data) written and waiting | 3.5–4.5 |
| 2 | **Storage manager** | Per-sink async writer tasks, batching, LRU cache, in-memory buffer for state-store outages, spool and replay, retention, health checks | 800 | 400 | 5–6 | **~15%** — registry, config types, simple fan-out; `FaultySink` ready for tests; cache, buffer and spool limits specified | 4.5–5.5 |
| 3 | **Enrichment** | DNS answer parser and IP-to-host cache, TLS ClientHello SNI, HTTP request and URL parsing with redaction (`privacy.url_query`), QUIC Initial decryption for SNI (`ring` 0.17); parser tests on recorded sample traffic. The HTTP request and URL parser is written in `crates/module-url` as the first module (specs 7.4.6); core enrichment keeps SNI, `Host`, DNS and QUIC | 1,200 | 500 | 7–9 | **~10%** — TLS detection, DNS cache; fixtures and fuzz seeds ready except QUIC | 6–8 |
| 4 | **Policy engine** | Learn / caution / alert modes, scoring rules (raw IP, unusual port, high-entropy names, new top-level domain, new process, rare host, threat list), alert dedupe and rate limits, automatic switch out of learn mode | 900 | 500 | 6–8 | **0%** code, design done — in `crates/policy`; scores, threshold, usual ports and entropy rule in the v1 config, checked against the 11 scenarios | 5–7 |
| 5 | **Daemon pipeline** | Wire sensor → enrichment → policy → storage; per-host and per-process counters; run as a systemd, launchd or Windows service; drop privileges. Run states for `scribe daemon` (specs 8.5): runtime metrics registry and health checks, counter reset, cache flush, live config reload (also SIGHUP) with the live / needs-restart split, hibernate and wake up (sensor stop and start again, `--for` timer on `Clock`, `learn_for` paused, `audit` events). Security: StrictModes file-mode checks at start, `daemon.max_hibernate` cap and `hibernated` alert, `audit` events for stops, crashes and refused calls, sequence + `prev_hmac` chain on audit and alert records | 1,500 | 450 | 9.5–11.5 | **~5%** — binary prints version and setup; Windows layout next to the app decided | 9.5–11.5 |
| 6 | **pcap sensor** (fallback) | libpcap / Npcap capture of SYN, UDP, DNS and ClientHello packets; reassemble the first bytes of each flow | 700 | 200 | 4–5 | **~2%** — stub; sensor conformance suite ready | 3.5–4.5 |
| 7 | **Linux eBPF sensor** | aya probes on `tcp_connect` / `udp_sendmsg` and cgroup sockets, a socket filter for packet contents, ring-buffer reader, process lookup via `/proc`. Security: privileged part only loads and attaches, keeps only `CAP_BPF` / `CAP_PERFMON`, root-only pinned maps | 1,700 (Rust + eBPF) | 350 | 11.5–15.5 | **~2%** — stub, draft raw records | 11.5–15.5 |
| 8 | **Windows ETW sensor** | Kernel-Network and DNS-Client providers, process path lookup, Npcap for packet contents. Security: service SID, processing as `NT SERVICE\scribed` where ETW allows | 1,300 | 230 | 11–13 | **~2%** — stub, draft raw records | 11–13 |
| 9 | **macOS Network Extension** | Swift `NEFilterDataProvider` (~1,000 Swift), XPC bridge in Rust (~500), container app and installer. Security: code-signing requirement checked both ways on XPC, versioned schema with size limits, decoder fuzzed | 1,650 (Swift + Rust) | 200 | 13–17 | **0%** — draft XPC message format only | 13–17 |
| 10 | **Local API and CLI** | gRPC (tonic) over a Unix socket or named pipe, access control by socket permissions and caller identity (read vs control calls); CLI commands `status`, `hosts`, `mode`, `alerts`, `baseline add/rm`, `alerts ack`, `export`; `scribe daemon status` (with `--json`, `--watch`), `health` (also `grpc.health.v1`), `reset`, `hibernate [--for]`, `wakeup`. Security: socket in a `root:scribe` `0750` directory, named-pipe access list with `first_pipe_instance` / `reject_remote_clients`, OS identity in request extensions, clients check the server, message / timeout / stream limits, `export` streamed and written by the CLI. Modules: `ListModules`, `ModuleStatus`, per-module services, `scribe modules` and module subcommands, per-module section in `daemon status` | 2,000 | 700 | 11.5–12.5 | **~10%** — CLI argument parsing, `--version`; UI mock API data defines the shapes; in `crates/api` + `proto/scribe/v1/` | 11–12 |
| 11 | **Alert outputs** | OS notifications on each platform, structured log, webhook. Security: HTTPS only (loopback excepted), no cross-host redirects, HMAC-signed webhooks with the secret from the keychain, optional pinning; threat-list download with optional `sha256` / `minisign` check, last good list kept, entry cap | 750 | 200 | 4.5–5.5 | **~5%** — `AlertOutput` interface, `RecordingAlertSink`; in `crates/alerts`, log output via `log.output` | 4.5–5.5 |
| 12 | **Postgres backend** | tokio-postgres with a deadpool connection pool, migrations, conformance tests against a Postgres container in CI. Security: TLS via `tokio-postgres-rustls`, default `verify-full`, `disable` / `prefer` rejected off loopback, optional client certificates; `INSERT`-only sink role, one role per host with row-level security; heartbeats | 1,100 | 250 | 6–7 | **~10%** — v1 schema and seed, stubs, CI job with Postgres 16 | 5.5–6.5 |
| 13 | **Packaging and release** | `.deb` / `.rpm`, MSI (WiX, keeps config / data / logs next to the app across upgrades), macOS `.pkg` with notarization, signing, install and uninstall scripts. Security: hardened systemd unit, `scribe` / `scribe-admin` groups and file modes, signed `SHA256SUMS` and build provenance, signed `.deb` / `.rpm` repositories; optional `storage.encrypt` (SQLCipher, AES-256-GCM spool, key in the OS secret store) | 1,000 (scripts/config + Rust) | 150 | 9–11 | **~15%** — Release workflow builds archives for 4 targets with checksums; installers left | 8–10 |
| 14 | **Hardening** | Fuzz the packet parsers, performance and memory tests under load, security review, user docs. Security: `cargo deny` / `cargo audit` in Tests, Actions pinned by SHA with minimal `permissions:` (can be done any time), review against specs 12.1.1 | 500 | 300 | 6–8 | **~10%** — fuzz targets and workflow; never run | 5–7 |
| | **Total** | | **~17,500** | **~5,200** | **118–147** | **phases 0 and 0b done** | **101.5–127.5** |

With a 20% buffer for unknowns, plan on **122–153 person-days remaining**. That's about 6–7½ months for one developer, or about 2–3 months for two or three working in parallel.

## Milestones

| Milestone | Phases | Result | Planned | Remaining |
|---|---|---|---|---|
| **M1: MVP** | 0, 0b, 1–6, 10, 11 | Runs on all three OSes using pcap (no process attribution), SQLite storage, all three modes, CLI including `scribe daemon`, notifications, local API access control, module framework with the URL module | 61.5–75.5 days | 47.5–58.5 days |
| **M2: Native sensors** | 7, 8, 9 | Process attribution and better hostname coverage on each OS; privilege split, XPC code signing | 35.5–45.5 days | 35.5–45.5 days |
| **M3: Production** | 12, 13, 14 | Postgres over TLS, signed installers and checksums, fuzzed parsers, security review | 21–26 days | 18.5–23.5 days |

**Parallel work:** after M1, the three native sensors (phases 7, 8 and 9) don't depend on each other, so they can go to different developers. Postgres (phase 12) can be done any time after phase 2.

## Next steps

In this order, because each one turns existing tests and data into real coverage:

1. **Phase 1, SQLite backend:** make the skipped `sqlite_conformance` tests pass against schema v2 (migrations `0001` and `0002`, both snapshots).
2. **Phase 3, enrichment:** SNI, `Host` and DNS parsers, the URL module's HTTP request parser with URL redaction (`scribe-module-url`), all against the 13 pcap fixtures; then QUIC with `ring` and a fixture checked against the RFC 9001 Appendix A sample packet.
3. **Phase 4, policy engine:** create `crates/policy`, the scenario runner and the rules with the v1 config values, against the 11 scenarios.
4. **Apply for Apple's Network Extension entitlement now**, so the wait overlaps M1 (risk 1).
5. **Any time, cheap:** add `cargo deny` / `cargo audit` to the Tests workflow and pin Actions by SHA (phase 14 work that needs no product code).

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
| Module framework (specs 7.4, Proposed): features as compiled-in modules with generic outputs (flow notes, module records, metric samples, module state); URL tracking becomes the first module; kernel metrics is the example of a later one | New phase 0b (8–10 days) before phase 1; phase 10 +2 days for module API and CLI plumbing; schema v2 before SQLite; `privacy.url_query` becomes `[modules.url] query`. M1 +10–12 days |
| Security design for every interaction (specs 12.1.1, NFR-17 – NFR-19; all Proposed) | +2,000 LOC, +730 test LOC, +14.5 days, following the spec's suggested order: phase 5 +1.5 (StrictModes, hibernate cap, audit chain), 7 +1.5, 8 +1, 9 +1 (privilege split, XPC signing), 10 +2 (API access and limits), 11 +1.5 (HTTPS, signed webhooks, threat-list checks), 12 +2 (Postgres TLS, roles, heartbeats), 13 +3 (service hardening, release signing, optional encryption at rest), 14 +1 (`cargo deny` / `audit`, pinned Actions, review). M1 +5 days, M2 +3.5, M3 +6 |

## Risks

1. **Apple's Network Extension entitlement and notarization:** approval can take weeks of waiting on top of the work. Apply during M1.
2. **eBPF across kernel versions:** use CO-RE (compile once, run everywhere) and keep pcap as the fallback for kernels older than 5.8.
3. **Windows packet contents:** ETW gives flows but not payloads, so SNI needs Npcap. A WFP driver would remove that dependency but requires EV signing; leave it for a later blocking feature.
4. **Hostname visibility:** DNS-over-HTTPS and Encrypted Client Hello hide hostnames. Detect and report these flows as "unresolved" rather than dropping them.
5. **Alert fatigue:** caution mode's scoring will need tuning on real traffic. Plan for a round of adjustments after M1.
6. **Module framework scope (new):** a general interface designed with only one real module risks fitting URL tracking alone. Keep the outputs generic, check the design against the kernel metrics sketch (specs 7.4.8) before freezing `scribe-module-api`, and mark it unstable until a second module exists.
7. **Security scope (new):** the 12.1.1 design touches every phase and three OSes. The privilege split and the API access checks are the riskiest parts: keep the privileged code tiny, test every control call as a read-only peer, and review both in phase 14. Encryption at rest (`storage.encrypt`) is optional and can slip past v1 without blocking a release.
8. **Minimum Rust version (resolved):** policy *follow dependencies*, 1.89 now. Remaining risk: a dependency may require a very recent Rust (aya 0.16 needs 1.98); that's accepted, since release binaries are built on current stable.

## Not included
- **Tauri UI:** about 4–6k LOC (TypeScript + Rust), 20–30 days. Test folders and mock API data already exist.
- **Blocking connections:** nftables, Network Extension verdicts, WFP; about 15–20 days.
- **Opt-in MITM module for full URLs inside TLS:** about 15 days; would be a module (specs 7.4).
- **Kernel metrics module (`kperf`):** TCP retransmits, RTT, run-queue delay via eBPF / ETW / `sysctl`; about 8–12 days after phase 0b and the native sensors (specs 7.4.8).
