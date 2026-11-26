# Test list

*2026-11-22, after phase 1; tags applied to every existing test. The catalogue of automated tests that make up the **fast run**: the tests in
[test-approach.md](test-approach.md) that need no privileges and no lab. "Exists" names the current test;
"Phase N" means it lands with that plan phase.*

## 1. Goals

- **Every test is isolated:** it creates what it needs, touches nothing another test uses, and leaves
  nothing behind.
- **Every test can run in parallel** with every other test, in any order.
- **The whole fast run takes 1–2 minutes** after the build (section 4).
- **Tags** let a run pick one kind of test: `smoke`, `functional`, `integration`, `scenario`.

Slow or privileged stages (sensor conformance on real OSes, end-to-end installs, fuzzing, performance,
soak, volume, UI browser tests) are outside the fast run; section 8 lists them.

## 2. Tags

Each test has exactly one tag.

| Tag | Checks | Rules |
|---|---|---|
| `smoke` | Critical functionality: the binaries start, the shipped config is valid, storage opens, the schema is consistent | Changes nothing outside its own temporary folder. **Live smoke** (against a running `scribed`) uses read-only calls only, at most 10 per run, and never changes mode, baseline, alerts or run state |
| `functional` | One piece of behaviour of one module: a parser, a rule, a config check, a storage method, a CLI command | Talks to its module directly, with test doubles for everything else |
| `integration` | Data passing from one module or service to another: config → storage, module host → storage manager → SQLite, CLI → API → daemon | Real modules on both sides of the boundary; doubles only beyond them |
| `scenario` | A full story through the pipeline: a scenario file from `testdata/scenarios/` played through sensor → enrichment → modules → policy → storage → alerts | Whole pipeline in-process with `FakeSensor`, `FakeClock`, `MemoryStore` / temporary SQLite, `RecordingAlertSink` |

### 2.1 Where tests live and how they carry their tag

Rust has no test tags, so the tag comes from **where the test lives** (layout option C, hybrid):

```
tests/                         crate scribe-tests: tests that cross crates
  Cargo.toml
  smoke/        main.rs + binaries.rs, config.rs, fixtures.rs, schema.rs, storage.rs   → tag smoke
  integration/  main.rs + daemon.rs, storage.rs                                       → tag integration
  scenario/     main.rs (the scenario runner arrives in phase 4)                       → tag scenario
  support/      lib.rs: shared helpers (paths, snapshots, SQLite stores, configs)
  bin/          scribed-under-test, scribe-under-test: the real binaries, built here so the
                smoke tests get CARGO_BIN_EXE_* (distinct names avoid clashing in target/)
  e2e/          install / upgrade / uninstall scripts (not Rust)
crates/<crate>/tests/functional/   main.rs + one file per area                         → tag functional
crates/<crate>/src/…               #[cfg(test)] mod tests { mod functional { … } }    → tag functional
```

- **Test binaries named after a tag** (`smoke`, `integration`, `scenario`, each crate's `functional`)
  give all their tests that tag; their own paths hold no tag module.
- **Unit tests inside source files** are only those that need private code (49 today: the config table
  in `daemon/src/config/tests.rs`, `config/load.rs`, `core/src/units.rs`, `core/src/platform.rs`,
  `test-support/src/packets/net.rs`). They sit in exactly one tag module, e.g.
  `units::tests::functional::parses_sizes`.
- New functional tests go to the crate's `tests/functional/`; new smoke, integration and scenario
  tests go to `tests/`.

| Run | Command |
|---|---|
| Fast run (all tags) | `cargo nextest run --workspace --all-features` |
| One tag | `cargo nextest run --workspace --all-features -E 'binary(smoke) \| test(/(^\|::)smoke::/)'` |
| Cross-crate tests only | `cargo nextest run -p scribe-tests` |
| One crate's functional tests | `cargo nextest run -p scribe-storage-sqlite` |
| Without nextest | `cargo test -p scribe-tests --test smoke` |
| Live smoke (phase 10) | `SCRIBE_SMOKE_SOCKET=/run/scribe/api.sock cargo nextest run -p scribe-live-smoke` |

**Runner:** `cargo-nextest` runs each test in its own process, which makes isolation stronger (no shared
panic hooks, statics or environment), shows per-test times, and enforces the time limits in
`.config/nextest.toml` (warn 2 s / kill 6 s; integration and scenario tests warn 5 s / kill 10 s).

`scripts/check-test-tags.sh` fails on any test without exactly one tag, by binary or module (doc examples
are not listed; the Tests workflow runs `cargo test --doc` for them).

## 3. Isolation and parallel rules

Every test follows these rules; review checks them.

| # | Rule | How |
|---|---|---|
| I-1 | Own files | `tempfile::tempdir()` per test; snapshots are copied in before use; never a fixed path such as `/tmp/x.db` |
| I-2 | Own ports | Bind `127.0.0.1:0` and read the port back; never a fixed port |
| I-3 | Own time | `FakeClock`; no `sleep` to wait for something. Waiting on a child process polls with a deadline |
| I-4 | No process-wide state | No `std::env::set_var`, no global panic hook changes, no `static mut`; child processes get their environment through `Command::env` |
| I-5 | Own database | Postgres tests create a schema named after the test (`t_<random>`) and drop it at the end; SQLite tests use their own file |
| I-6 | Read-only shared data | `testdata/`, `config/` and fixtures are only read; nothing in a test writes the repository |
| I-7 | Deterministic | Random input comes from a fixed seed; timing checks use generous budgets so a loaded machine doesn't fail them |
| I-8 | Live smoke stays separate | Live smoke runs alone against a daemon nobody else is testing; it never runs inside the fast run |

**Known violations:**
1. ~~`scribe-module-conformance` swapped the global panic hook per call.~~ Fixed: the hook is installed once
   and stays quiet only on the thread that expects a panic.
2. Postgres conformance shares the database in `SCRIBE_TEST_POSTGRES_URL` (I-5); it needs a schema per test
   before it is enabled in phase 12.
3. The module suite's hook time budget (2 ms average in debug) can flake on a loaded machine (I-7); measure
   with more rounds or raise the budget for debug builds.

## 4. Time budget

**Measured now** (Apple M2 Max, 12 cores, debug build, after compiling, `cargo nextest`, after phase 6): 390 tests
(387 run, 3 ignored) plus doc examples in 44 test binaries, **1.4 s** wall clock; no test reaches the
2 s warning. Before
tagging, `cargo test` took 5 s, mostly in one test (`catches_every_fault`), now split into one test per
fault with a shorter case for the slow-hook fault.

**Target for the finished fast run:** planned **≤ 60 s**, with **100% contingency ≤ 120 s** (the hard
limit). Compile time is not included.

| Tag | Tests now | Tests planned (M3) | Planned wall time | Per-test limit (warn / kill) |
|---|---|---|---|---|
| `smoke` | 16 | ~20 (+ 6 live) | ≤ 5 s | 2 s / 6 s |
| `functional` | 430 | ~450 | ≤ 30 s | 2 s / 6 s (suites ≤ 5 s) |
| `integration` | 31 | ~35 | ≤ 15 s | 5 s / 10 s |
| `scenario` | 30 | 32 | ≤ 10 s | 5 s / 10 s |
| **Total** | **507** (after phase 11) | **~540** | **≤ 60 s** (limit 120 s) | |

**How the budget holds:** runs are parallel, so wall time ≈ the longer of (total test time ÷ cores) and
the slowest single test. With ~400 tests averaging under 0.5 s and no test over 10 s, a 4-core CI runner
stays under 60 s. A test that needs longer moves out of the fast run (section 8).

**Watch list:** binary start-up tests (≈ 0.1–0.4 s each), the module conformance suite (≈ 2 s), SQLite
volume-ish tests, scenario runs with long `FakeClock` spans (time is simulated, so they stay fast).

## 5. Catalogue

Columns: **ID**, **test** (current name, or planned name), **checks**, **isolation** (what it creates),
**time** (estimate), **status**.

### 5.1 Smoke

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| SMK-01 | `scribed_prints_its_version`, `scribe_prints_its_version` | Both binaries start and print `<name> <version>` | Child process | 0.1 s | Exists (`tests/smoke/binaries.rs`) |
| SMK-02 | `checks_the_shipped_config` | `scribed --check-config` accepts `config/scribe.toml`; URL module enabled | Child process, reads repo | 0.1 s | Exists |
| SMK-03 | `shipped_file_equals_built_in_defaults` | Shipped config = built-in defaults | In memory | < 10 ms | Exists |
| SMK-04 | `runs_until_sigterm_and_stops_cleanly` | `scribed` starts, creates and migrates `state.db` / `events.db`, starts the URL module, stops on SIGTERM with exit 0 | Temp dir, child process | 0.3 s | Exists (Unix) |
| SMK-05 | `committed_fixtures_match_generator` | Committed fixtures and fuzz seeds match the generator | Reads repo | 0.1 s | Exists |
| SMK-06 | `*_has_one_migration_per_schema_version`, `every_schema_version_has_a_*` (SQLite, Postgres; `tests/smoke/schema.rs`) | Migrations and snapshots match `SCHEMA_VERSION` | Reads repo | < 10 ms | Exists |
| SMK-07 | `built_in_modules_match_their_manifests` | Every built-in module has a valid manifest | In memory | < 10 ms | Exists |
| SMK-08 | `cli_definition_is_valid` | The `scribe` command tree is consistent | In memory | < 10 ms | Exists |
| SMK-09 | `sqlite_opens_and_reports_healthy` | A new SQLite file migrates and reports `Health::Ok` | Temp dir | 20 ms | Exists (`tests/smoke/storage.rs`) |
| SMK-10 | `windows_service_starts_and_stops` | `scribed` runs as a service and stops on service stop | Child process | 1 s | Phase 5 (Windows) |
| SMK-11 | `api_answers_health` | In-process daemon on a temp socket answers `Health` | Temp socket | 0.2 s | Phase 10 |
| SMK-12 | `cli_reaches_daemon` | `scribe daemon health` against SMK-11's daemon exits 0 | Temp socket | 0.2 s | Phase 10 |
| SMK-13 | `pcap_decoder_reads_every_fixture` | The pcap decoder reads every committed fixture in `testdata/pcap/` | Reads repo | < 10 ms | Exists |
| SMK-14 | `policy_loads_default_scores` | Policy engine builds from the default config | In memory | < 10 ms | Phase 4 |
| SMK-15 | `release_archive_layout` | A packed archive holds both binaries, readme and config | Temp dir | 0.5 s | Phase 13 |
| SMK-16 | `ui_mocks::every_mock_scenario_matches_the_api_messages`, `the_check_catches_a_field_the_api_does_not_have` | Every UI mock scenario parses as the API messages (unknown fields refused), run states are `running` / `hibernating`, `extends` targets exist | Reads repo | < 10 ms | Exists |

**Live smoke** (crate `scribe-live-smoke`, phase 10; runs against a live daemon, read-only, ≤ 10 calls):

| ID | Test | Checks | Time | Status |
|---|---|---|---|---|
| SMK-L1 | `live_health` | `scribe daemon health` exits 0 within 2 s | 0.1 s | Phase 10 |
| SMK-L2 | `live_status_shape` | `daemon status --json` parses; run state, mode, version present | 0.1 s | Phase 10 |
| SMK-L3 | `live_versions_match` | CLI and daemon report the same version | 0.1 s | Phase 10 |
| SMK-L4 | `live_hosts_page` | `hosts --json --limit 1` returns a page | 0.1 s | Phase 10 |
| SMK-L5 | `live_modules_running` | `modules --json` lists `url` as running | 0.1 s | Phase 10 |
| SMK-L6 | `live_grpc_health` | `grpc.health.v1` reports `SERVING` | 0.1 s | Phase 13 (live suite); covered against a test daemon by `api::the_standard_health_service_answers` |

### 5.2 Functional

Grouped by area. Rows that cover many existing tests list the test names in the **Test** column.

**Core and units**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-C01 | `units::tests::*` (14) | Durations, sizes, percentages: parse, format, round-trip, errors, TOML | In memory | < 10 ms | Exists |
| FUN-C02 | `platform::tests::*` (9) | Default paths per OS, `/proc/meminfo`, total RAM, volume size | Temp dir | < 10 ms | Exists |
| FUN-C03 | `module::tests::*`, `event::tests::*` (5) | Notes, observations cut to 4 KiB, `unresolved()` | In memory | < 10 ms | Exists |
| FUN-C04 | `sensor::tests::*`, `error::tests::*` (4) | Error messages stay stable | In memory | < 10 ms | Exists |

**Config and logging (daemon)**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-CF01 | `rejects_bad_configs_with_their_line` | ~40 bad configs give the right message, line and column | In memory | < 10 ms | Exists |
| FUN-CF02 | `discovery_order`, `named_files_must_exist`, `loads_files_and_built_in_defaults` | `--config` > `SCRIBE_CONFIG` > OS default > built-in | Temp dir | < 10 ms | Exists |
| FUN-CF03 | `resolves_paths_against_data_dir`, `resolves_limits`, `percentages_need_host_facts` | Paths and percentages resolved with `FakeHost` | In memory | < 10 ms | Exists |
| FUN-CF04 | `effective_config_*`, `summary_hides_credentials` | `--check-config` output reloads to the same config; secrets hidden | In memory | < 10 ms | Exists |
| FUN-CF05 | module config tests (`modules_can_be_switched_off`, `sinks_may_subscribe_to_module_kinds`, `deprecated_url_query_*`, `the_default_module_list_*`) | `[modules]` rules, module kinds in sinks, deprecated key | In memory | < 10 ms | Exists |
| FUN-CF06 | other `config::tests::*` (8) | Defaults, partial tables, OS rules, built kinds | In memory | < 10 ms | Exists |
| FUN-CF07 | `config_reload_live_vs_restart` | Reload applies live settings, reports restart-only ones, rejects a bad file and keeps the old one | In memory | < 10 ms | Phase 5 |
| FUN-CF08 | `policy_scores_for_module_signals` | `[policy.scores]` accepts namespaced module reasons; unknown ones rejected with their line | In memory | < 10 ms | Phase 4 |
| FUN-LG01 | `logging::tests::*` (9) | Levels, `SCRIBE_LOG`, text / JSON, daily and size rotation, stderr fallback | Temp dir | 20 ms | Exists |

**Daemon binary and lifecycle**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-D01 | `usage_errors_exit_with_2`, `a_named_config_must_exist`, `rejects_a_bad_config_with_its_line`, `rejects_a_bad_log_filter`, `rejects_an_unknown_module` | Exit codes and messages for bad input | Temp dir, child process | 0.1 s each | Exists |
| FUN-D02 | `reads_scribe_config_from_the_environment`, `warns_about_the_deprecated_url_query` | `SCRIBE_CONFIG`, deprecation warning | Temp dir, child process | 0.1 s each | Exists |
| FUN-D03 | `app::tests::*` (4) | Arguments, config errors exit 2, `serve` creates folders and stops | Temp dir | 20 ms | Exists |
| FUN-D04 | `health_reports_reasons` | Healthy / degraded / unhealthy with reasons and exit codes | In memory | < 10 ms | Phase 5 |
| FUN-D05 | `reset_clears_runtime_counters_only` | `reset --counters` / `--caches`; stored history untouched | Temp dir | 20 ms | Phase 5 |
| FUN-D06 | `hibernate_is_capped_and_alerts` | `--for` capped by `max_hibernate`; `hibernated` alert; nothing recorded | `FakeClock` | < 10 ms | Phase 5 |
| FUN-D07 | `strict_modes_refuse_writable_files` | Start refused for group / other-writable config, `data_dir`, `file:` credential | Temp dir | < 10 ms | Phase 5 (Unix) |
| FUN-D08 | `audit_chain_detects_tampering` | Sequence + `prev_hmac` catch a deleted and an edited row | Temp dir | 20 ms | Phase 5 |

**CLI and local API**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-CL01 | `cli::parses_every_command`, `rejects_bad_input`, `describes_commands_as_typed`, `scribe::usage_errors_exit_with_2` | Every command parses; bad input rejected; exit codes | In memory / child | < 0.1 s | Exists |
| FUN-CL02 | `cli::parses_the_daemon_commands_and_their_aliases`, `the_socket_comes_from_the_flag_then_the_environment` | `daemon status/health/reset/hibernate/wakeup` with flags and aliases; `--socket` / `SCRIBE_SOCKET` | In memory | < 10 ms | Exists |
| FUN-CL03 | `output::*` (12); `--json` in INT-12 and SCN-UI | Status (critical first), health, hosts, hourly, alerts with notes, baseline, edits, reset, modules, audit report | In memory | < 10 ms | Exists |
| FUN-CL04 | `scribe::a_file_that_is_not_a_socket_is_refused`, `an_absent_daemon_is_reported_with_exit_1`, `health_prints_unhealthy_and_exits_1_when_unreachable`; `socket::root_only_clients_refuse_a_user_socket`, `pipe::a_pipe_server_must_be_system_or_the_caller` (Windows CI) | CLI refuses a non-socket, a socket not owned by root / itself, a pipe server not SYSTEM; unreachable daemon exits 1 | Temp socket / child | 20 ms | Exists |
| FUN-API01 | `access::*` (7), `pipe::control_calls_follow_the_policy`; daemon side in INT-11 | Read calls open, control calls for root / the admin group, identity from the transport, refusals audited | In memory / temp socket | 50 ms | Exists |
| FUN-API02 | `socket::oversized_messages_are_refused_and_the_server_keeps_serving`, `many_clients_are_served_at_once`, stale / live socket handling | Oversized messages cut off; concurrent clients; live socket refused, stale one replaced | Temp socket | 0.1 s | Exists (slow-call and stream caps set in `limits`, not exercised) |
| FUN-API03 | `module-url api::*` (3) | URL module service: defaults and caps, host normalised, identity required; `scribe url` output | In memory | < 10 ms | Exists |
| FUN-API03 | `export_streams_to_the_caller` | Export streamed; daemon never writes a client path | Temp socket | 50 ms | Phase 10 |

**Enrichment and sensors (decoding only)**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-E01 | `tls::detects_*`, `empty_is_unknown` (3) | TLS / plaintext detection from first bytes | In memory | < 10 ms | Exists |
| FUN-E02 | `tls::reads_sni_from_tls13_and_tls12`, `a_hello_split_over_two_records_is_reassembled`, `names_are_normalised_and_checked`, `reads_alpn`; fixtures in INT-18 | SNI from TLS 1.2 / 1.3, split records, name checks; fixtures `tls*` (fragmented, out-of-order, truncated, no-SNI) end to end | In memory / reads fixtures | 20 ms | Exists |
| FUN-E03 | `http::*` (6), `enricher::host_header_names_a_plaintext_flow`; fixtures in INT-18 | `Host` from origin, proxy and CONNECT forms; IP literals refused; `http_plain`, `http_keepalive` end to end | In memory / reads fixtures | < 10 ms | Exists |
| FUN-E04 | `dns::*` (5) | A / AAAA / CNAME answers, compression, shortest TTL on the chain, TTL cap and expiry with `FakeClock`, entry limit | In memory | < 10 ms | Exists |
| FUN-E05 | `tls::no_sni_and_ech`, `enricher::ech_sets_the_flag_and_the_flow_counts_as_unresolved`; `tls_ech` in INT-18 | Outer name, `ech` true, `unresolved()` true | In memory / reads fixtures | < 10 ms | Exists |
| FUN-E06 | `quic::quic_initial_rfc9001_vector`, `quic_v2_initial_rfc9369_vector`, `the_test_builder_reproduces_both_rfc_packets`, `a_hello_split_over_initials_is_joined_in_any_order`, `initials_for_another_connection_id_are_ignored`, `quic_fixtures_name_their_flows` (+3) | QUIC v1 / v2 Initial decrypted with `ring`; SNI from the RFC packets; a second implementation reproduces them; CRYPTO reassembly | In memory | < 10 ms | Exists |
| FUN-E07 | `tls::every_prefix_is_incomplete_never_a_panic`, `quic::random_datagrams_never_panic`, `mutated_rfc_packets_never_panic`, `dns::queries_failures_and_garbage_are_rejected`, `quic::fuzz_seeds_reach_the_parsers`; `malformed` in INT-18 | Prefixes, mutations and random input: no panic; fuzz seeds still reach the parsers | In memory | 0.2 s | Exists |
| FUN-E08 | `enricher::*` (9) | Name order SNI > `Host` > sensor name > DNS cache; security for TCP and UDP; QUIC Initials turn UDP flows into named QUIC flows | In memory | < 10 ms | Exists |
| FUN-D01 | `pipeline::*` (12) | Pipeline writes, DNS answers, QUIC holding and timeout, run states, cache reset | `FakeClock` | < 10 ms | Exists |
| FUN-D02 | `chain::*` (5) | Audit chain seal, verify, gaps, edits, restart, codec round trip; StrictModes | Temp dir | < 10 ms | Exists |
| FUN-D03 | `service::*` (5; plus `service::privileges_keeper_restarts_capture_as_a_user`, ignored: root, run alone in the Sensors workflow), `daemon_user_is_unix_only`, `max_hibernate_*`, `reload_*` | Service files, privilege drop (as root on Linux: only the keeper thread can open a packet socket and start eBPF capture), systemd notify (Linux), config keys of phase 5, reload planner | Temp dir | < 10 ms | Exists |
| FUN-SN01 | `pcap_decoder_matches_expected_flows`, `decode::*` (7), `file::*` (5), `flows::*` (9), `sensor::*` (5) | Each fixture gives its `NewFlow` and `Payload` observations with the right first bytes; link types, fragments, IPv6 headers, pcap formats, timeouts, closes, local addresses, payload switch, limits, device choice | Reads fixtures | 0.1 s | Exists |
| FUN-SN05 | `scribe-process` functional (24): `parse::*` (3), `resolver::*` (8), `live::*` (4), `join::*` (9); daemon `the_pcap_sensor_gets_process_lookup_unless_turned_off` | `/proc/net` lines (IPv4, IPv6, v4-mapped, UDP, listen, garbage); matching by 5-tuple, wildcard UDP and v4-mapped; refresh at most every 100 ms (`FakeClock`); unreadable table; the wrapper fills in new flows only; this process's own TCP and UDP sockets found in the real table of each system; scan budget: a slow read spaces out the next ones (capped at 5 s), a fast one resets; load check: 100,000 sockets in a fake table, and 400 own connections found with one real read under 1 s (4.7 ms on a Mac, unprivileged); `join` (native sensors' connection reports with packet observations): by exact addresses, by port for unbound UDP, TTL, a reported path wins over the lookup, lookup once per 5 s per pid; late reports waited for up to the sensor's hold in order, DNS answers and known processes passed at once | In memory / loopback sockets | < 50 ms | Exists |
| FUN-SN02 | `scribe-sensor-linux` functional (6): `samples::ebpf_samples_decode`, `record::*` (5) | `testdata/events/linux-ebpf/*`: kernel records (`struct scribe_flow` v2, through their bytes, path from the record: `/proc` never read) joined with a pcap fixture's packets give the expected observations with pid and path, closes included; kernel path read back, a long one keeps its tail, offsets past the end mean none; records of both families, v4-mapped addresses, bad sizes / versions / kinds / families refused, no panic on any byte (the join itself: FUN-SN05 `join::*`) | Reads samples | < 10 ms | Exists (phase 7) |
| FUN-SN03 | `scribe-sensor-windows` functional (17): `samples::etw_samples_decode`, `events::*` (5), `dns::*` (3), `flows::*` (2), `processes::*` (6) | `testdata/events/windows-etw/*`: Kernel-Network and DNS-Client events (through their bytes) with or without a pcap fixture's packets give the expected observations with pid and path, and DNS answers name the flows through the DNS cache; events 12 / 28 / 42 / 58 read back, ports and addresses in network order, v4-mapped addresses as IPv4, other events skipped, short ones refused, no panic on any length; event 3008 read back with its addresses (aliases skipped); answers as a DNS message under the queried name (300 s TTL, at most 128 addresses), none for failures or names DNS can't carry; ETW-only flows: every TCP attempt, UDP once per socket and destination until 30 s quiet; Kernel-Process events 1 / 2 / 15 read back (Windows 7 and Windows 10+ layouts, `ImageName` found after any fixed fields), no image for `System` or a missing NUL, NT device paths to drive paths (case-insensitive, `\??\`, unknown devices kept), a stopped process's path kept 60 s, the table capped at 65,536 | Reads samples | < 10 ms | Exists (phase 8 step 1) |
| FUN-SN04 | `xpc_messages_decode` | `testdata/events/macos-ne/*` → expected observations; bad messages rejected | Reads samples | < 10 ms | Only with option 9A (later) |
| FUN-SN05 | `cases_use_distinct_ports`, `every_case_reaches_its_local_server` | Sensor traffic generator works on loopback | Ports `:0` | 50 ms | Exists |

**Modules**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-M01 | module-api `config::tests::*`, `manifest::tests::*`, `tests::*` (11) | `ConfigDoc` lines, manifest naming rules | In memory | < 10 ms | Exists |
| FUN-M02 | `catches_*` (7), `a_*_module_passes` (3) | Module suite passes good modules and catches each of 7 faults | In memory | 0.4 s | Exists |
| FUN-M03 | `url_module_conforms`, `url::*` (5) | URL module passes the suite; `query` config with deprecated key | In memory | 0.3 s | Exists |
| FUN-M04 | `module_host.rs` (10) | Notes, panic isolation, budget, source ticks, pause / resume, reload, full queue, restart failure | `FakeClock` | 50 ms | Exists |
| FUN-M05 | `hook::notes_records_and_counts_a_plaintext_request`, `tls_flows_get_no_url`; `http_plain`, `http_keepalive` in INT-18 | Request URL from both fixtures (both requests of the kept-alive one); user info removed | In memory / reads fixtures | < 10 ms | Exists |
| FUN-M06 | `privacy::*` (4) | Every `query` mode against the specs 12.2 examples; origin form with odd ports | In memory | < 10 ms | Exists |
| FUN-M07 | `hook::hash_*`, `short_hash_is_hmac_sha256_cut_to_six_digits`, `switching_to_hash_while_running_loads_the_key`, `a_bad_hash_key_reference_points_at_the_value` (6) | `hash` mode: HMAC-SHA256 vector, key created once in `data_dir` or read from `hash_key`, no key → no start | Temp dir | < 10 ms | Exists |

**Storage**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-S01 | `codec::tests::*`, `model::tests::*` (6) | Row codec round-trips every kind; schema 1 rows; bad rows rejected; kind names | In memory | < 10 ms | Exists |
| FUN-S02 | `reference_state_store_conforms`, `reference_event_sink_conforms` | Conformance suites pass on the in-memory doubles | In memory | < 10 ms | Exists |
| FUN-S03 | `sqlite_state_store_conforms`, `sqlite_event_sink_conforms`, `state_and_sink_can_share_a_file` | SQLite passes both suites | Temp dir | 30 ms | Exists |
| FUN-S04 | `schema.rs` (4) | New file, both snapshots migrate, newer schema refused, unopenable path | Temp dir | 30 ms | Exists |
| FUN-S05 | `state.rs` (5), `sink.rs` (4) | Seen times, literal filters, baselines, clock use, reopen; time windows, rollback, schema 1 and v2 rows | Temp dir | 50 ms | Exists |
| FUN-S06 | `counters_are_sums` (proptest, 24 cases) | Random update sequences: counters equal the sums, seen times min / max, flags only turn on | Temp dir | 0.1 s | Exists |
| FUN-S07 | `many_writers_on_one_file_lose_nothing` | Four threads with their own connections to one file: no lost updates | Temp dir | 0.1 s | Exists |
| FUN-S08 | `sqlite_in_memory_*_conforms` | Both suites on an in-memory database | In memory | 20 ms | Exists |
| FUN-S09 | conformance `retention_removes_old_events` | The `EventSink` retention call (SQLite now, Postgres in phase 12) | Temp dir | 20 ms | Exists |
| FUN-S10 | `postgres_*_conforms` (sink runs; state store ignored until implemented) | Postgres passes both suites | Own schema | 0.5 s | Sink exists (option 12C; needs `SCRIBE_TEST_POSTGRES_URL`) |
| FUN-S11 | `settings::*` (5) in `scribe-storage-postgres`; daemon `spots_plaintext_to_remote_servers` and config errors | TLS forced for remote servers (`prefer` too), `sslmode=disable` refused off loopback, loopback without TLS, schema names, credentials from a secret reference and never printed, an unreachable server reported down | In memory | < 10 ms | Exists (`ca` / client certificates later) |
| FUN-SM01 | `manager.rs` registry and routing tests (9) | Registry kinds and roles, routing by kind, errors | In memory | < 10 ms | Exists |
| FUN-SM02 | `writer.rs` (6) | Batching by size and time, slow sink isolated, full queue drops, hourly retention, shutdown (paused Tokio time) | In memory | < 10 ms | Exists |
| FUN-SM03 | `a_slow_sink_does_not_hold_up_others` | A slow sink doesn't delay other sinks | In memory | < 10 ms | Exists |
| FUN-SM04 | `spool.rs` (8) | Spool, ordered replay, back-off, size and disk limits, restart, shared budget | Temp dir | 50 ms | Exists |
| FUN-SM05 | `state.rs` (7) | Outage buffer: order, count and memory limits, links by name, poison writes, health | In memory | < 10 ms | Exists |
| FUN-SM06 | `cache.rs` (5) | LRU by host count and memory, write-through updates, baselines, clear | In memory | < 10 ms | Exists |

**Policy and alerts**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-P01 | `signals::*` (6), `engine::threat_lists_match_names_and_ips`, `scores_of_zero_disable_signals_and_close_events_are_ignored` | Every signal alone: raw IP, unusual port, entropy, new TLD, new process, threat list; 0 disables | In memory | < 10 ms | Exists |
| FUN-P02 | `engine::caution_mode_follows_the_table`, `spec_8_3_examples_score_as_documented`, `caution_prefers_the_score_reason_over_plaintext`, `alert_mode_alerts_on_unlisted_hosts_and_plaintext`, `module_signals_use_their_configured_score` | Sum, cap at 100, threshold 50, top reason, reason order, module scores | In memory | < 10 ms | Exists |
| FUN-P03 | `signals::entropy_matches_hand_computed_values`, `random_looking_names_are_flagged_and_ordinary_ones_are_not`, `entropy_is_bounded_by_the_alphabet` | Label length and bits-per-character limits | In memory | < 10 ms | Exists |
| FUN-P04 | `engine::alerts_repeat_once_per_window_per_host_and_process`, `acknowledged_alerts_stay_silent`, `a_repeat_with_new_notes_updates_the_earlier_alert` | Window per host + process from the last alert; acknowledged stays silent; notes added to the earlier alert | `FakeClock` | < 10 ms | Exists |
| FUN-P05 | `engine::learn_ends_after_learn_for_and_switches_mode`, `a_mode_switch_applies_to_the_next_flow`, `a_paused_learn_timer_ends_later_by_the_pause` | `learn_for` switch; mode change from the next flow; paused while hibernating | `FakeClock` | < 10 ms | Exists |
| FUN-A01 | `log::log_output_writes_alerts`, `log_output_line_without_host_and_summary`; `throttle::*` (3), `dispatch::*` (6) | Alert log line format (text and JSON); rate limit per output with one summary per window; lanes deliver in order, drop when full, count failures, close with a grace | In memory | < 10 ms | Exists |
| FUN-A02 | `scribe-net` functional (11): `signature_matches_independent_test_vectors`, `url::*`, `client::*`, `tls::*`; `scribe-alerts` `webhook::*` (3); daemon `webhooks_are_checked_when_the_file_is_read` | HMAC vectors (computed with Python), HTTPS only except loopback, same-origin redirects only (POST only on 307 / 308), chunked and capped bodies, timeouts, self-signed TLS refused without its pin and accepted with it; signed JSON payload, retries on 429 / 5xx only, summaries; config checks | Port `:0` | 1.5 s | Exists |
| FUN-A03 | `scribe-cli` `notify::*` (4) | Notification text; `scribe notify` against `MockApiServer` with a fake notifier: rate limit and summary (`FakeClock`), `--min-score` with `hibernated` always shown, waiting for scribed, catching up after a restart without repeats | Temp socket | ~1 s | Exists |
| FUN-A04 | daemon `threats::*` (6), `config::tests::threat_list_download_checks_are_validated`, `threat_sources_are_files_or_downloads_with_a_cache` | Pinned SHA-256; minisign signatures made with ring checked by `minisign-verify` (tampered body, other key, missing, garbage); entry cap for files and downloads; downloads from a local server (signature URL, 404, http to a remote host refused); last good copy at start; a refused refresh keeps the last good list and its copy; config checks | Temp dir, port `:0` | 0.4 s | Exists |
| FUN-SC01 | `scribe-secrets` functional (10 on each system); daemon `set_secret_stores_piped_or_generated_keys` | References parse and print back; `file:` read, mode and owner checks, race-safe creation, shared directory refused, `store` replaces privately; other systems' stores `Unsupported`; DPAPI round trip and garbage (Windows); keychain missing item, round trip with `SCRIBE_TEST_KEYCHAIN=1` (macOS); Secret Service without a bus (Linux); `scribed --set-secret` | Temp dir | < 10 ms | Exists |

**Test support**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-T01 | `doubles.rs` (5), `ipv4_header_checksum_verifies_to_zero`, `fixture_names_are_unique` | Test doubles, packet builder, fixture names | In memory | < 10 ms | Exists |

### 5.3 Integration

| ID | Test | From → to | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|---|
| INT-01 | `manager_publishes_through_sqlite`, `the_running_storage_writes_through_to_sqlite` | Storage manager (direct and running: writers, spool, buffer, cache) → SQLite | Published events and host writes read back from the files | Temp dir | 30 ms | Exists |
| INT-02 | `serve_creates_folders_and_stops_on_shutdown` | Config → resolve → storage manager → backends | `serve()` builds storage from settings and shuts down | Temp dir | 30 ms | Exists (`tests/integration/daemon.rs`) |
| INT-03 | `reads_rows_written_by_schema_1`, `reads_the_v2_snapshot` | Snapshot → migration → codec → sink | Old rows readable after migration | Temp dir | 30 ms | Exists |
| INT-04 | `released_snapshots_migrate_to_the_latest_schema` | Snapshot → migration → state store | Seeded hosts readable after migration | Temp dir | 30 ms | Exists (`tests/integration/storage.rs`) |
| INT-05 | `module_output_is_stored_and_its_state_survives_a_restart` | Module host → output queue → storage manager → SQLite events and `module_state` | `url.request` records and the request counter stored | Temp dir | 100 ms | Exists (`tests/integration/daemon.rs`) |
| INT-06 | `module_output_is_stored_and_its_state_survives_a_restart` | SQLite `module_state` → module host start → module | The counter continues after a restart | Temp dir | (same test) | Exists |
| INT-07 | `config_reload_applies_live_keys_and_refuses_broken_files` | Config file → reload → policy, modules | Live keys applied, restart keys reported, broken file refused | Temp dir | 50 ms | Exists |
| INT-08 | `dns_answer_names_a_later_flow` | Enrichment DNS cache → TLS flow without SNI | `dns_cname_then_tls`, `dns_aaaa_then_tls` hostnames (packet builders; fixtures also in INT-18) | In memory | 20 ms | Exists (`tests/integration/enrich.rs`) |
| INT-09 | `pcap_to_enriched_flows` | pcap replay → pipeline (enrichment, QUIC holding, URL module, policy) | Each fixture's full JSON expectation incl. `notes.url`, `ech` | Reads fixtures | 20 ms | Exists (`tests/integration/enrich.rs`) |
| INT-10 | `pipeline_stores_flows_counters_and_alerts` | `FakeSensor` → enrichment → modules → policy → SQLite | Hosts, per-process counters, alert state, flow and alert events | Temp dir | 50 ms | Exists |
| INT-11 | `alerts::an_alert_reaches_a_signed_webhook` | `FakeSensor` → policy → dispatcher → webhook output → `scribe-net` → local receiver | The raw-IP alert arrives as JSON, signed with the key from the `file:` reference; `machine` set | Temp dir, port `:0` | 50 ms | Exists |
| INT-12 | `cli::every_command_works_against_a_running_daemon`, `control_commands_outside_the_admin_group_exit_1`, `audit_verify_finds_deleted_and_edited_records`, `module_subcommands_reach_the_module_service`, `a_module_that_is_not_enabled_is_named` | Real `scribe` → local API (temp socket) → daemon → SQLite | Every command incl. export file mode, hourly counters, audit verify after tampering, `scribe url list` | Temp dir + socket | 0.5 s | Exists (`tests/integration/cli.rs`) |
| INT-13 | `api::*` (11) | Daemon state → API: status, health, `grpc.health.v1`, hosts, alerts, watch stream, baseline, export, modules; control calls and their audit events; alert state across restarts; bucket pruning; a second daemon on a busy socket; process attribution hit rate in status, `attribution_low` and degraded health below 50% | Run state, counters, critical metrics, audit messages | Temp dir + socket | 1 s | Exists (`tests/integration/api.rs`) |
| INT-14 | `secrets_to_backends` | Secrets crate → Postgres credentials, URL hash key | `file:` references resolved where used | Temp dir | 20 ms | URL key exists (FUN-M07); Postgres in phase 12 |
| INT-15 | `storage::the_running_storage_writes_through_to_postgres` | Running storage manager (writer task, spool) → Postgres sink, SQLite state store | Three flows written, nothing spooled, health ok, query total 3 | Own schema | 0.2 s | Exists (needs `SCRIBE_TEST_POSTGRES_URL`) |
| INT-16 | `xpc_bridge_with_fake_extension` | Fake extension process → XPC bridge → ingest | Flow messages arrive as observations; unsigned peer refused | Child process | 0.5 s | Phase 9 (macOS) |
| INT-17 | `ui_commands_against_mock_api` | Tauri commands → `MockApiServer` | Requests and error mapping | Temp socket | 0.2 s | Later (UI); `MockApiServer` exists |
| INT-19 | `commands_drive_the_run_states` | `Command`s → running daemon → storage | Hibernate, reset, wakeup, status; audit events and the `hibernated` alert stored | Temp dir | 50 ms | Exists |
| INT-20 | `an_unclean_stop_is_audited_and_the_chain_verifies` | Two daemon runs → audit chain | Unclean stop audited; the chain of both runs verifies | Temp dir | 100 ms | Exists |
| INT-18 | → INT-09 | The test-side frame reader was replaced by the pcap sensor's replay in phase 6 | — | — | — | Merged into INT-09 |

### 5.4 Scenario

One test per file in `testdata/scenarios/`, played by the scenario runner in `tests/scenario`. Until the
pipeline exists (phase 5) it plays events through `ModuleHost`, `Policy` and `MemoryStore` with `FakeClock`;
from phase 5 it uses the real pipeline with `FakeSensor`, a temporary SQLite state store, `MemorySink` and
`RecordingAlertSink`. Simulated time makes hour-long scenarios take milliseconds. Guard tests:
`every_scenario_file_has_a_test` and `a_wrong_expectation_fails`.

| ID | Scenario file | Story | Time | Status |
|---|---|---|---|---|
| SCN-01 | `learn-adds-hosts-no-alerts` | Learn mode records everything, alerts on nothing | 20 ms | Exists |
| SCN-02 | `learn-auto-switch` | `learn_for` ends, caution starts alerting | 20 ms | Exists |
| SCN-03 | `mode-switch-via-api` | Mode change applies from the next flow | 20 ms | Exists |
| SCN-04 | `caution-ordinary-new-host` | Ordinary new host stays quiet | 20 ms | Exists |
| SCN-05 | `caution-raw-ip` | Raw IP alerts as `raw_ip` | 20 ms | Exists |
| SCN-06 | `caution-high-entropy-domain` | Random-looking domain alerts | 20 ms | Exists |
| SCN-07 | `caution-plaintext-known-host` | Plaintext to a listed host alerts with its URL | 20 ms | Exists |
| SCN-08 | `caution-unusual-port-known-process` | 30 points stay quiet | 20 ms | Exists |
| SCN-09 | `caution-unusual-port-new-process` | 55 points alert | 20 ms | Exists |
| SCN-10 | `caution-new-tld-quiet` | 45 points stay quiet | 20 ms | Exists |
| SCN-11 | `caution-threat-list` | Threat list alerts at 100 | 20 ms | Exists |
| SCN-12 | `alert-unlisted-host` | Alert mode alerts on unlisted hosts only | 20 ms | Exists |
| SCN-13 | `alert-dedupe-window` | One alert per window per host + process | 20 ms | Exists |
| SCN-14 | `alert-acknowledged` | Acknowledged alert stays silent | 20 ms | Exists |
| SCN-15 | `counters-exact` | Exact counters per host and per process | 20 ms | Exists |
| SCN-16 | `hostname-unresolved` | ECH and nameless flows tracked and flagged | 20 ms | Exists |
| SCN-17 | `module-signal-scored` | A module signal lifts the score and names the alert | 20 ms | Exists |
| SCN-18 | `daemon-hibernate-capped` | Hibernation capped, alerting, recording nothing | 20 ms | Exists |
| SCN-19 | `daemon-wakeup-and-reset` | Wakeup resumes; reset keeps history | 20 ms | Exists |
| SCN-20 | `restart_keeps_hosts_counters_and_baseline` (integration test) | Hosts, counters and learned baseline survive a restart on the same SQLite files | 100 ms | Exists (`tests/integration/daemon.rs`) |
| SCN-21 | `storage_outage_and_replay` | State store down mid-run: buffer, drops counted, replay in order | 30 ms | Covered below the pipeline by the storage-manager tests (`state.rs`); a pipeline-level run with `FaultySink` in phase 12 |
| SCN-22 | `sink_outage_spools` | Event sink down: spool, then replay; other sinks unaffected | 30 ms | Covered below the pipeline by the storage-manager tests (`spool.rs`, `writer.rs`); pipeline-level run in phase 12 |
| SCN-23 | `module_panics_mid_run` | A test module panics; it is switched off, health degraded, the rest keeps going | 20 ms | Covered by FUN-M04 (`module_host.rs`), which the pipeline uses unchanged |
| SCN-24 | `config_reload_mid_run` → INT-07 | Policy and module changes by reload apply from the next flow | 50 ms | Exists (as INT-07) |
| SCN-25 | `profiles_are_isolated` (integration test) | A host learned in `work` is unlisted in `home` | 150 ms | Exists (`tests/integration/daemon.rs`) |
| SCN-26 | `runner_rejects_bad_scenarios` | The runner refuses unknown keys and bad times with the line (or event index) | < 10 ms | Exists |
| SCN-UI | `cli_mocks::*` (8) | The real `scribe` against `MockApiServer` playing the UI mock scenarios: typical day, first launch, hibernating, degraded / module failed, version mismatch, 10,000 hosts, daemon down, control commands changing the mock | 0.3 s | Exists (`tests/scenario/cli_mocks.rs`, Unix) |

## 6. Coverage of the test approach

| Test approach section | Covered by |
|---|---|
| 3 Isolation doubles | All tags; rules in section 3 |
| 4 UI | INT-17; browser tests in section 8 |
| 5.1 Decoding | FUN-E01 – E07, FUN-SN01 – SN04, SMK-13 |
| 5.2 OS hookup | Section 8 (privileged) |
| 6 Daemon | FUN-CF*, FUN-D*, FUN-M04, INT-02, INT-05 – INT-11, SCN-* |
| 7 Storage | FUN-S*, FUN-SM*, INT-01, INT-03, INT-04, INT-15 |
| 7a Modules | FUN-M01 – M07, INT-05 – INT-07, SCN-17, SCN-23 |
| 9 Security | FUN-D07, D08, FUN-CL04, FUN-API01 – 03, FUN-A02, A04, FUN-S11, INT-16 |

## 7. Changes needed to reach this list

1. ~~Add `cargo-nextest` to the Tests workflow and the local check, with `.config/nextest.toml`.~~ Done;
   the Tests workflow runs smoke first, then the whole fast run, and fails it over 120 s.
2. ~~Move existing tests into tag modules; split `built_in_registry_has_sqlite`.~~ Done; then moved to the
   hybrid layout (section 2.1): `tests/` for smoke and integration, `tests/functional/` per crate.
3. Isolation violations (section 3): panic hook fixed; Postgres schema per test (phase 12) and the debug
   hook budget remain.
4. ~~Check that every test sits in a tag module.~~ Done: `scripts/check-test-tags.sh`, in the Tests workflow.
5. Report per-tag counts and wall time in `status.md` after each phase.

## 8. Outside the fast run

These stages keep their own time budgets (test approach section 11) and never block the 1–2 minute run.

| Stage | Tests | Budget |
|---|---|---|
| Privileged sensor conformance | `pcap_sensor_conforms` and `ebpf_sensor_conforms` (both pass in the Linux build container, kernel 6.18 arm64: `scripts/build/linux.sh run --privileged cargo test -p scribe-sensor-conformance --test functional -- --ignored`; the eBPF one checks pid and path of TLS, HTTP, TCP and UDP flows; both green on the Ubuntu x86_64 runner in Sensor tests run `45658825832`) and the native sensors on each OS (`etw_sensor_conforms` on the Windows runner: ETW alone, pid and path of each case, 5 s per event; `pcap_sensor_conforms` there only with Npcap); Linux kernel matrix 5.8, 5.15, 6.1, 6.18 in job `kernels` (all green in run `45712541202`) (virtme-ng guests, `scripts/ci/kernel-check.sh`: eBPF and pcap conformance plus `service::privileges_keeper_restarts_capture_as_a_user`; pcap only on a kernel without BTF) | < 2 h |
| End-to-end | `tests/e2e/` on installed packages | 1–2 days with the release checklist |
| Fuzzing | `fuzz/` targets, 30 min each | < 2 h |
| Performance, soak, volume | 1,000 connections/s; 24 h soak; 10M events | Before release |
| UI browser tests | Vitest, Playwright, visual, `tauri-driver` | < 15 min (when the UI exists) |
| Live smoke | SMK-L1 – L6 against a running daemon | < 10 s |
