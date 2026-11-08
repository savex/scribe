# Implementation plan for scribe

*Last updated 2026-11-08, at commit `fd170fb`. Progress details: [status.md](status.md).
Decisions and config values: [scribe-conventions skill](../.claude/skills/scribe-conventions/SKILL.md).*

**Assumptions**
- One experienced Rust developer.
- "LOC" means Rust source lines without blanks and comments, except where another language is named.
- Tests are counted separately.
- Effort is in person-days of focused work and doesn't include waiting on Apple or code-signing vendors.

## Progress so far

- **Product code:** skeleton only. Interfaces, schemas, stubs and the version plumbing exist; nothing captures, stores or alerts yet. Automated tests cover 5% of product code.
- **Test infrastructure (done):** test doubles, packet builders and fixture generator, storage and sensor conformance suites, 13 pcap fixtures with expected results, 11 daemon scenarios, draft raw sensor records, v1 schema snapshots, fuzz targets, UI mock data, end-to-end scripts. This was not a separate phase in the original plan; it front-loads most of the test work of phases 1–6.
- **CI, versioning and tooling (done):** tag-based versioning, 8 GitHub workflows (Release and Version tracking automatic, the rest manual), VSCodium launch and task configs, conventions skill and `CLAUDE.md`.

## Phases

| # | Phase | Main work | Prod LOC | Test LOC | Planned (days) | Status | Remaining (days) |
|---|---|---|---|---|---|---|---|
| 0 | **Foundations** | Upgrade Rust; add tokio, serde, toml, tracing, thiserror; config loading; logging; CI on Linux, macOS and Windows | 400 | 50 | 2–3 | **~70%** — Rust upgraded (stable for development, 1.70 minimum kept), CI and versioning done. Left: dependencies, config loading, logging | 1–1.5 |
| 1 | **SQLite backend** | rusqlite (bundled), migration runner, every StateStore and EventSink method, JSON payloads, WAL; must pass conformance | 900 | 250 | 4–5 | **~10%** — v1 schema and snapshot, stubs; conformance tests written and waiting | 3.5–4.5 |
| 2 | **Storage manager** | Per-sink async writer tasks, batching, LRU cache, spool and replay, retention, health checks | 800 | 400 | 5–6 | **~15%** — registry, config types, simple fan-out; `FaultySink` ready for tests | 4.5–5.5 |
| 3 | **Enrichment** | DNS answer parser and IP-to-host cache, TLS ClientHello SNI, HTTP request and URL parsing, QUIC Initial decryption for SNI (`ring` 0.17); parser tests on recorded sample traffic | 1,200 | 500 | 7–9 | **~10%** — TLS detection, DNS cache; fixtures and fuzz seeds ready except QUIC | 6–8 |
| 4 | **Policy engine** | Learn / caution / alert modes, scoring rules (raw IP, unusual port, high-entropy names, new top-level domain, new process, rare host, threat list), alert dedupe and rate limits, automatic switch out of learn mode | 900 | 500 | 6–8 | **0%** — 11 scenarios ready | 5.5–7.5 |
| 5 | **Daemon pipeline** | Wire sensor → enrichment → policy → storage; per-host and per-process counters; run as a systemd, launchd or Windows service; drop privileges | 900 | 200 | 6–8 | **~5%** — binary prints version and setup | 6–8 |
| 6 | **pcap sensor** (fallback) | libpcap / Npcap capture of SYN, UDP, DNS and ClientHello packets; reassemble the first bytes of each flow | 700 | 200 | 4–5 | **~2%** — stub; sensor conformance suite ready | 3.5–4.5 |
| 7 | **Linux eBPF sensor** | aya probes on `tcp_connect` / `udp_sendmsg` and cgroup sockets, a socket filter for packet contents, ring-buffer reader, process lookup via `/proc` | 1,500 (Rust + eBPF) | 300 | 10–14 | **~2%** — stub, draft raw records | 10–14 |
| 8 | **Windows ETW sensor** | Kernel-Network and DNS-Client providers, process path lookup, Npcap for packet contents | 1,200 | 200 | 10–12 | **~2%** — stub, draft raw records | 10–12 |
| 9 | **macOS Network Extension** | Swift `NEFilterDataProvider` (~1,000 Swift), XPC bridge in Rust (~500), container app and installer | 1,500 (Swift + Rust) | 150 | 12–16 | **0%** — draft XPC message format only | 12–16 |
| 10 | **Local API and CLI** | gRPC (tonic) over a Unix socket or named pipe, access control by socket permissions; CLI commands `status`, `hosts`, `mode`, `alerts`, `baseline add/rm`, `alerts ack`, `export` | 1,100 | 300 | 6–7 | **~10%** — CLI argument parsing, `--version`; UI mock API data defines the shapes | 5.5–6.5 |
| 11 | **Alert outputs** | OS notifications on each platform, structured log, webhook | 500 | 100 | 3–4 | **~5%** — `AlertOutput` interface, `RecordingAlertSink` | 3–4 |
| 12 | **Postgres backend** | tokio-postgres with a deadpool connection pool, migrations, conformance tests against a Postgres container in CI | 800 | 150 | 4–5 | **~10%** — v1 schema and seed, stubs, CI job with Postgres 16 | 3.5–4.5 |
| 13 | **Packaging and release** | `.deb` / `.rpm`, MSI (WiX), macOS `.pkg` with notarization, signing, install and uninstall scripts | 600 (scripts/config) | — | 6–8 | **~15%** — Release workflow builds archives for 4 targets with checksums; installers left | 5–7 |
| 14 | **Hardening** | Fuzz the packet parsers, performance and memory tests under load, security review, user docs | 500 | 300 | 5–7 | **~10%** — fuzz targets and workflow; never run | 4–6 |
| | **Total** | | **~13,500** | **~3,600** | **90–117** | **~4% of product LOC** | **83–109.5** |

With a 20% buffer for unknowns, plan on **100–131 person-days remaining**. That's about 5–6½ months for one developer, or about 2–3 months for two or three working in parallel.

## Milestones

| Milestone | Phases | Result | Planned | Remaining |
|---|---|---|---|---|
| **M1: MVP** | 0–6, 10, 11 | Runs on all three OSes using pcap (no process attribution), SQLite storage, all three modes, CLI, notifications | 43–55 days | 38.5–50 days |
| **M2: Native sensors** | 7, 8, 9 | Process attribution and better hostname coverage on each OS | 32–42 days | 32–42 days |
| **M3: Production** | 12, 13, 14 | Postgres, signed installers, fuzzed parsers | 15–20 days | 12.5–17.5 days |

**Parallel work:** after M1, the three native sensors (phases 7, 8 and 9) don't depend on each other, so they can go to different developers. Postgres (phase 12) can be done any time after phase 2.

## Next steps

In this order, because each one turns existing tests and data into real coverage:

1. **Finish phase 0:** add tokio, serde, toml, tracing and thiserror (check each one's minimum Rust version), config loading from `config/scribe.example.toml`, logging. Add the first unit tests for `core`, `storage-manager` and `cli`, which have none.
2. **Phase 1, SQLite backend:** make the skipped `sqlite_conformance` tests pass.
3. **Phase 3, enrichment:** SNI, HTTP and DNS parsers against the 13 pcap fixtures; then QUIC with `ring` and a fixture checked against the RFC 9001 Appendix A sample packet.
4. **Phase 4, policy engine:** the scenario runner plus the rules, against the 11 scenarios.
5. **Apply for Apple's Network Extension entitlement now**, so the wait overlaps M1 (risk 1).

## Decisions since the first version

| Decision | Effect on the plan |
|---|---|
| Storage backends limited to SQLite and Postgres | ClickHouse, OpenSearch, file sinks and external gRPC storage plugins dropped |
| `ring` 0.17 for QUIC Initial decryption | Phase 3 adds a C-compiled dependency; fixture checked against RFC 9001 Appendix A |
| Rust 1.70 kept as the minimum version, development on current stable | New dependencies may need older versions pinned (risk 6) |
| All test workflows manual, only Release and Version tracking automatic | The test approach's "nightly" stage is run by hand |
| Versions come from `v*` git tags | Release work in phase 13 is down to installers and signing |

## Risks

1. **Apple's Network Extension entitlement and notarization:** approval can take weeks of waiting on top of the work. Apply during M1.
2. **eBPF across kernel versions:** use CO-RE (compile once, run everywhere) and keep pcap as the fallback for kernels older than 5.8.
3. **Windows packet contents:** ETW gives flows but not payloads, so SNI needs Npcap. A WFP driver would remove that dependency but requires EV signing; leave it for a later blocking feature.
4. **Hostname visibility:** DNS-over-HTTPS and Encrypted Client Hello hide hostnames. Detect and report these flows as "unresolved" rather than dropping them.
5. **Alert fatigue:** caution mode's scoring will need tuning on real traffic. Plan for a round of adjustments after M1.
6. **Minimum Rust version 1.70:** the latest versions of several common crates already need newer Rust (e.g. RustCrypto `aes` needs 1.89, `aws-lc-rs` 1.71). Expect to pin older versions or raise the minimum; decide before phase 1 adds the first dependencies.

## Not included
- **Tauri UI:** about 4–6k LOC (TypeScript + Rust), 20–30 days. Test folders and mock API data already exist.
- **Blocking connections:** nftables, Network Extension verdicts, WFP; about 15–20 days.
- **Opt-in MITM module for full URLs inside TLS:** about 15 days.
