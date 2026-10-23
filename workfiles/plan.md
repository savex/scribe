# Implementation plan for scribe

**Assumptions**
- One experienced Rust developer.
- "LOC" means Rust source lines without blanks and comments, except where another language is named.
- Tests are counted separately.
- Effort is in person-days of focused work and doesn't include waiting on Apple or code-signing vendors.

## Phases

| # | Phase | Main work | Prod LOC | Test LOC | Effort (days) |
|---|---|---|---|---|---|
| 0 | **Foundations** | Upgrade Rust; add tokio, serde, toml, tracing, thiserror; config loading; logging; CI on Linux, macOS and Windows | 400 | 50 | 2–3 |
| 1 | **SQLite backend** | rusqlite (bundled), migration runner, every StateStore and EventSink method, JSON payloads, WAL; must pass conformance | 900 | 250 | 4–5 |
| 2 | **Storage manager** | Per-sink async writer tasks, batching, LRU cache, spool and replay, retention, health checks | 800 | 400 | 5–6 |
| 3 | **Enrichment** | DNS answer parser and IP-to-host cache, TLS ClientHello SNI, HTTP request and URL parsing, QUIC Initial decryption for SNI; parser tests on captured sample traffic | 1,200 | 500 | 7–9 |
| 4 | **Policy engine** | Learn / caution / alert modes, scoring rules (raw IP, unusual port, high-entropy names, new top-level domain, new process, rare host, threat list), alert dedupe and rate limits, automatic switch out of learn mode | 900 | 500 | 6–8 |
| 5 | **Daemon pipeline** | Wire sensor → enrichment → policy → storage; per-host and per-process counters; run as a systemd, launchd or Windows service; drop privileges | 900 | 200 | 6–8 |
| 6 | **pcap sensor** (fallback) | libpcap / Npcap capture of SYN, UDP, DNS and ClientHello packets; reassemble the first bytes of each flow | 700 | 200 | 4–5 |
| 7 | **Linux eBPF sensor** | aya probes on `tcp_connect` / `udp_sendmsg` and cgroup sockets, a socket filter for packet contents, ring-buffer reader, process lookup via `/proc` | 1,500 (Rust + eBPF) | 300 | 10–14 |
| 8 | **Windows ETW sensor** | Kernel-Network and DNS-Client providers, process path lookup, Npcap for packet contents | 1,200 | 200 | 10–12 |
| 9 | **macOS Network Extension** | Swift `NEFilterDataProvider` (~1,000 Swift), XPC bridge in Rust (~500), container app and installer | 1,500 (Swift + Rust) | 150 | 12–16 |
| 10 | **Local API and CLI** | gRPC (tonic) over a Unix socket or named pipe, access control by socket permissions; CLI commands `status`, `hosts`, `mode`, `baseline add/rm`, `alerts ack`, `export` | 1,100 | 300 | 6–7 |
| 11 | **Alert outputs** | OS notifications on each platform, structured log, webhook | 500 | 100 | 3–4 |
| 12 | **Postgres backend** | tokio-postgres with a deadpool connection pool, migrations, conformance tests against a Postgres container in CI | 800 | 150 | 4–5 |
| 13 | **Packaging and release** | `.deb` / `.rpm`, MSI (WiX), macOS `.pkg` with notarization, signing, install and uninstall scripts | 600 (scripts/config) | — | 6–8 |
| 14 | **Hardening** | Fuzz the packet parsers, performance and memory tests under load, security review, user docs | 500 | 300 | 5–7 |
| | **Total** | | **~13,500** | **~3,600** | **90–117** |

With a 20% buffer for unknowns, plan on **110–140 person-days**. That's about 5½–7 months for one developer, or about 2½–3½ months for two or three working in parallel.

## Milestones

| Milestone | Phases | Result | Effort |
|---|---|---|---|
| **M1: MVP** | 0–6, 10, 11 | Runs on all three OSes using pcap (no process attribution), SQLite storage, all three modes, CLI, notifications | 43–55 days |
| **M2: Native sensors** | 7, 8, 9 | Process attribution and better hostname coverage on each OS | 32–42 days |
| **M3: Production** | 12, 13, 14 | Postgres, signed installers, fuzzed parsers | 15–20 days |

**Parallel work:** after M1, the three native sensors (phases 7, 8 and 9) don't depend on each other, so they can go to different developers. Postgres (phase 12) can be done any time after phase 2.

## Risks

1. **Apple's Network Extension entitlement and notarization:** approval can take weeks of waiting on top of the work. Apply during M1.
2. **eBPF across kernel versions:** use CO-RE (compile once, run everywhere) and keep pcap as the fallback for kernels older than 5.8.
3. **Windows packet contents:** ETW gives flows but not payloads, so SNI needs Npcap. A WFP driver would remove that dependency but requires EV signing; leave it for a later blocking feature.
4. **Hostname visibility:** DNS-over-HTTPS and Encrypted Client Hello hide hostnames. Detect and report these flows as "unresolved" rather than dropping them.
5. **Alert fatigue:** caution mode's scoring will need tuning on real traffic. Plan for a round of adjustments after M1.

## Not included
- **Tauri UI:** about 4–6k LOC (TypeScript + Rust), 20–30 days.
- **Blocking connections:** nftables, Network Extension verdicts, WFP; about 15–20 days.
- **Opt-in MITM module for full URLs inside TLS:** about 15 days.
