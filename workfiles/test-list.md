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

**Measured now** (Apple M2 Max, 12 cores, debug build, after compiling, `cargo nextest`): 183 tests
(180 run, 3 ignored) plus 1 doc example in 21 test binaries, **0.6 s** wall clock; no test reaches the
2 s warning. Before
tagging, `cargo test` took 5 s, mostly in one test (`catches_every_fault`), now split into one test per
fault with a shorter case for the slow-hook fault.

**Target for the finished fast run:** planned **≤ 60 s**, with **100% contingency ≤ 120 s** (the hard
limit). Compile time is not included.

| Tag | Tests now | Tests planned (M3) | Planned wall time | Per-test limit (warn / kill) |
|---|---|---|---|---|
| `smoke` | 13 | ~20 (+ 6 live) | ≤ 5 s | 2 s / 6 s |
| `functional` | 165 | ~330 | ≤ 30 s | 2 s / 6 s (suites ≤ 5 s) |
| `integration` | 5 | ~25 | ≤ 15 s | 5 s / 10 s |
| `scenario` | 0 | 26 | ≤ 10 s | 5 s / 10 s |
| **Total** | **183** | **~400** | **≤ 60 s** (limit 120 s) | |

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
| SMK-13 | `pcap_decoder_reads_every_fixture` | The pcap decoder reads all 14 fixtures without error | Reads repo | 0.1 s | Phase 6 |
| SMK-14 | `policy_loads_default_scores` | Policy engine builds from the default config | In memory | < 10 ms | Phase 4 |
| SMK-15 | `release_archive_layout` | A packed archive holds both binaries, readme and config | Temp dir | 0.5 s | Phase 13 |

**Live smoke** (crate `scribe-live-smoke`, phase 10; runs against a live daemon, read-only, ≤ 10 calls):

| ID | Test | Checks | Time | Status |
|---|---|---|---|---|
| SMK-L1 | `live_health` | `scribe daemon health` exits 0 within 2 s | 0.1 s | Phase 10 |
| SMK-L2 | `live_status_shape` | `daemon status --json` parses; run state, mode, version present | 0.1 s | Phase 10 |
| SMK-L3 | `live_versions_match` | CLI and daemon report the same version | 0.1 s | Phase 10 |
| SMK-L4 | `live_hosts_page` | `hosts --json --limit 1` returns a page | 0.1 s | Phase 10 |
| SMK-L5 | `live_modules_running` | `modules --json` lists `url` as running | 0.1 s | Phase 10 |
| SMK-L6 | `live_grpc_health` | `grpc.health.v1` reports `SERVING` | 0.1 s | Phase 10 |

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
| FUN-CL01 | `cli::tests::*` (4), `commands_report_they_are_not_implemented_yet` | Every command parses; bad input rejected; exit codes | In memory / child | < 0.1 s | Exists |
| FUN-CL02 | `daemon_subcommands_parse` | `daemon status/health/reset/hibernate/wakeup`, `modules`, `--json` | In memory | < 10 ms | Phase 10 |
| FUN-CL03 | `json_output_shapes` | `--json` output of each command against `MockApiServer` mock data | Temp socket | 50 ms | Phase 10 |
| FUN-CL04 | `refuses_a_fake_server` | CLI refuses a socket not owned by root / a pipe server not SYSTEM | Temp socket | 20 ms | Phase 10 |
| FUN-API01 | `read_and_control_access` | Every call: allowed for its access class, refused and audited otherwise (fake peer identities) | In memory | 50 ms | Phase 10 |
| FUN-API02 | `limits_cut_off_abuse` | Oversized messages, slow calls, too many streams cut off | Temp socket | 0.5 s | Phase 10 |
| FUN-API03 | `export_streams_to_the_caller` | Export streamed; daemon never writes a client path | Temp socket | 50 ms | Phase 10 |

**Enrichment and sensors (decoding only)**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-E01 | `tls::tests::*` (3) | TLS / plaintext detection from first bytes | In memory | < 10 ms | Exists |
| FUN-E02 | `sni_from_fixtures` | SNI from TLS 1.2 / 1.3, fragmented, out-of-order; none from truncated / no-SNI | Reads fixtures | 20 ms | Phase 3 |
| FUN-E03 | `host_header_from_fixtures` | `Host` from `http_plain`, `http_keepalive` | Reads fixtures | < 10 ms | Phase 3 |
| FUN-E04 | `dns_cache_follows_answers` | A / AAAA / CNAME answers, TTL expiry with `FakeClock` | In memory | < 10 ms | Phase 3 |
| FUN-E05 | `ech_sets_the_flag` | `tls_ech`: outer name, `ech` true, `unresolved()` true | Reads fixtures | < 10 ms | Phase 3 |
| FUN-E06 | `quic_initial_rfc9001_vector` | QUIC Initial decrypted with `ring`; SNI from the RFC 9001 Appendix A packet | In memory | < 10 ms | Phase 3 |
| FUN-E07 | `parsers_survive_malformed_input` | `malformed`, `tls_truncated` and 1,000 seeded random inputs: no panic | In memory | 0.2 s | Phase 3 |
| FUN-SN01 | `pcap_decoder_matches_expected_flows` | Each pcap fixture decodes to its JSON expectations (`kind`, `head`) | Reads fixtures | 0.1 s | Phase 6 |
| FUN-SN02 | `ebpf_samples_decode` | `testdata/events/linux-ebpf/*` → expected observations | Reads samples | < 10 ms | Phase 7 |
| FUN-SN03 | `etw_samples_decode` | `testdata/events/windows-etw/*` → expected observations | Reads samples | < 10 ms | Phase 8 |
| FUN-SN04 | `xpc_messages_decode` | `testdata/events/macos-ne/*` → expected observations; bad messages rejected | Reads samples | < 10 ms | Phase 9 |
| FUN-SN05 | `cases_use_distinct_ports`, `every_case_reaches_its_local_server` | Sensor traffic generator works on loopback | Ports `:0` | 50 ms | Exists |

**Modules**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-M01 | module-api `config::tests::*`, `manifest::tests::*`, `tests::*` (11) | `ConfigDoc` lines, manifest naming rules | In memory | < 10 ms | Exists |
| FUN-M02 | `catches_*` (7), `a_*_module_passes` (3) | Module suite passes good modules and catches each of 7 faults | In memory | 0.4 s | Exists |
| FUN-M03 | `url_module_conforms`, URL `tests::*` (6) | URL module passes the suite; `query` config with deprecated key | In memory | 0.3 s | Exists |
| FUN-M04 | `module_host.rs` (10) | Notes, panic isolation, budget, source ticks, pause / resume, reload, full queue, restart failure | `FakeClock` | 50 ms | Exists |
| FUN-M05 | `url_parser_on_fixtures` | Request URL from `http_plain` and both requests of `http_keepalive`; user info removed | Reads fixtures | < 10 ms | Phase 3 |
| FUN-M06 | `url_privacy_table` | Every `query` mode against the specs 12.2 examples | In memory | < 10 ms | Phase 3 |
| FUN-M07 | `url_hash_uses_the_secret_key` | `hash` mode with a key from the secrets crate (`file:` backend) | Temp dir | < 10 ms | Phase 3 |

**Storage**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-S01 | `codec::tests::*`, `model::tests::*` (6) | Row codec round-trips every kind; schema 1 rows; bad rows rejected; kind names | In memory | < 10 ms | Exists |
| FUN-S02 | `reference_state_store_conforms`, `reference_event_sink_conforms` | Conformance suites pass on the in-memory doubles | In memory | < 10 ms | Exists |
| FUN-S03 | `sqlite_state_store_conforms`, `sqlite_event_sink_conforms`, `state_and_sink_can_share_a_file` | SQLite passes both suites | Temp dir | 30 ms | Exists |
| FUN-S04 | `schema.rs` (4) | New file, both snapshots migrate, newer schema refused, unopenable path | Temp dir | 30 ms | Exists |
| FUN-S05 | `state.rs` (5), `sink.rs` (4) | Seen times, literal filters, baselines, clock use, reopen; time windows, rollback, schema 1 and v2 rows | Temp dir | 50 ms | Exists |
| FUN-S06 | `counters_are_sums` (proptest) | Random update sequences: counters equal the sums, flags only turn on | Temp dir | 0.5 s | Phase 2 |
| FUN-S07 | `many_writers_one_host` | Many tasks and two connections to one file: no lost updates, no lock errors | Temp dir | 0.3 s | Phase 2 |
| FUN-S08 | `sqlite_in_memory_conforms` | Both suites on an in-memory database | In memory | 20 ms | Phase 2 |
| FUN-S09 | `retention_removes_old_events` | The `EventSink` retention call, both backends | Temp dir | 20 ms | Phase 2 |
| FUN-S10 | `postgres_*_conforms` | Postgres passes both suites | Own schema | 0.5 s | Phase 12 (needs `SCRIBE_TEST_POSTGRES_URL`) |
| FUN-S11 | `postgres_tls_rules` | `sslmode` rules, `verify-full` default | In memory | < 10 ms | Phase 12 |
| FUN-SM01 | `manager.rs` registry and routing tests (9) | Registry kinds and roles, routing by kind, errors | In memory | < 10 ms | Exists |
| FUN-SM02 | `batches_by_size_and_time` | Per-sink batching with `FakeClock` | In memory | < 10 ms | Phase 2 |
| FUN-SM03 | `failing_sink_isolated` | A failing `FaultySink` doesn't delay other sinks | In memory | 20 ms | Phase 2 |
| FUN-SM04 | `spool_replays_in_order` | Spool and replay; oldest dropped at limits, drops counted | Temp dir | 50 ms | Phase 2 |
| FUN-SM05 | `state_outage_buffer` | Buffer while the state store is down; oldest dropped; replay | In memory | 20 ms | Phase 2 |
| FUN-SM06 | `host_cache_limits` | LRU by host count and memory; re-read on miss | In memory | 20 ms | Phase 2 |

**Policy and alerts**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-P01 | `each_signal_scores` | Every signal alone: raw IP, unusual port, entropy, new TLD, new process, threat list | In memory | < 10 ms | Phase 4 |
| FUN-P02 | `scores_sum_cap_and_name_the_top_reason` | Sum, cap at 100, threshold 50, top reason | In memory | < 10 ms | Phase 4 |
| FUN-P03 | `entropy_rule_boundaries` | Label length and bits-per-character limits | In memory | < 10 ms | Phase 4 |
| FUN-P04 | `dedupe_and_acknowledge` | Window per host + process; acknowledged stays silent | `FakeClock` | < 10 ms | Phase 4 |
| FUN-P05 | `learn_timer` | `learn_for` switch; paused while hibernating | `FakeClock` | < 10 ms | Phase 4 |
| FUN-A01 | `log_output_writes_alerts` | Alert log line format | Temp dir | < 10 ms | Phase 11 |
| FUN-A02 | `webhook_signing_and_https` | HMAC test vectors, HTTPS only, no cross-host redirects (local test server) | Port `:0` | 50 ms | Phase 11 |
| FUN-A03 | `notification_adapters` | OS notification calls through a fake OS interface | In memory | < 10 ms | Phase 11 |
| FUN-A04 | `threat_list_integrity` | Bad checksum rejected; last good list kept; entry cap | Temp dir | < 10 ms | Phase 11 |
| FUN-SC01 | `secrets_file_backend` | `file:` references: read, mode checks, missing file errors | Temp dir | < 10 ms | Phase 3 |

**Test support**

| ID | Test | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|
| FUN-T01 | `doubles.rs` (5), `ipv4_header_checksum_verifies_to_zero`, `fixture_names_are_unique` | Test doubles, packet builder, fixture names | In memory | < 10 ms | Exists |

### 5.3 Integration

| ID | Test | From → to | Checks | Isolation | Time | Status |
|---|---|---|---|---|---|---|
| INT-01 | `manager_publishes_through_sqlite` | Storage manager → SQLite sink | Published events read back through the sink | Temp dir | 30 ms | Exists |
| INT-02 | `serve_creates_folders_and_stops_on_shutdown` | Config → resolve → storage manager → backends | `serve()` builds storage from settings and shuts down | Temp dir | 30 ms | Exists (`tests/integration/daemon.rs`) |
| INT-03 | `reads_rows_written_by_schema_1`, `reads_the_v2_snapshot` | Snapshot → migration → codec → sink | Old rows readable after migration | Temp dir | 30 ms | Exists |
| INT-04 | `released_snapshots_migrate_to_the_latest_schema` | Snapshot → migration → state store | Seeded hosts readable after migration | Temp dir | 30 ms | Exists (`tests/integration/storage.rs`) |
| INT-05 | `module_output_reaches_storage` | Module host → output queue → storage manager → SQLite events and `module_state` | Records, metrics and state written | Temp dir, `FakeClock` | 50 ms | Phase 2 (with `TagModule`) |
| INT-06 | `module_state_survives_restart` | SQLite `module_state` → module host start → module | Stored state handed back at start | Temp dir | 50 ms | Phase 2 |
| INT-07 | `config_reload_reaches_modules` | Config reload → module host → module settings | Live keys applied, restart keys reported | Temp dir | 20 ms | Phase 5 |
| INT-08 | `dns_answer_names_a_later_flow` | Enrichment DNS cache → TLS flow without SNI | `dns_cname_then_tls`, `dns_aaaa_then_tls` hostnames | Reads fixtures | 20 ms | Phase 3 |
| INT-09 | `pcap_to_enriched_flows` | pcap decoder → enrichment → URL module | Each fixture's full JSON expectation incl. `notes.url`, `ech` | Reads fixtures | 0.1 s | Phase 6 |
| INT-10 | `pipeline_stores_a_flow` | `FakeSensor` → enrichment → modules → counters → policy → storage | One flow becomes a host, counters and a stored event | Temp dir, `FakeClock` | 50 ms | Phase 5 |
| INT-11 | `policy_alert_reaches_outputs_and_store` | Policy → alert outputs + `AlertState` + alert event | Alert delivered once and stored | Temp dir | 30 ms | Phases 4, 11 |
| INT-12 | `cli_api_daemon_round_trip` | CLI → local API (temp socket) → daemon → storage | `hosts`, `mode`, `baseline add` round-trip | Temp dir + socket | 0.3 s | Phase 10 |
| INT-13 | `api_status_reflects_daemon` | Daemon state → API `Status` → CLI `daemon status --json` | Run state, counters, modules match | Temp socket | 0.2 s | Phase 10 |
| INT-14 | `secrets_to_backends` | Secrets crate → Postgres credentials, URL hash key | `file:` references resolved where used | Temp dir | 20 ms | Phases 3, 12 |
| INT-15 | `postgres_sink_through_manager` | Storage manager → Postgres sink (TLS) | Events and module data stored | Own schema | 0.5 s | Phase 12 |
| INT-16 | `xpc_bridge_with_fake_extension` | Fake extension process → XPC bridge → ingest | Flow messages arrive as observations; unsigned peer refused | Child process | 0.5 s | Phase 9 (macOS) |
| INT-17 | `ui_commands_against_mock_api` | Tauri commands → `MockApiServer` | Requests and error mapping | Temp socket | 0.2 s | Later (UI) |

### 5.4 Scenario

One test per file in `testdata/scenarios/`, played by the scenario runner (phase 4; run-state actions
need phase 5, request counts and URL notes need phase 3). Each runs in-process with `FakeSensor`,
`FakeClock`, a temporary SQLite state store, `MemorySink` and `RecordingAlertSink`; simulated time makes
hour-long scenarios take milliseconds.

| ID | Scenario file | Story | Time | Needs |
|---|---|---|---|---|
| SCN-01 | `learn-adds-hosts-no-alerts` | Learn mode records everything, alerts on nothing | 20 ms | Phase 4 |
| SCN-02 | `learn-auto-switch` | `learn_for` ends, caution starts alerting | 20 ms | Phase 4 |
| SCN-03 | `mode-switch-via-api` | Mode change applies from the next flow | 20 ms | Phase 4 (API action) |
| SCN-04 | `caution-ordinary-new-host` | Ordinary new host stays quiet | 20 ms | Phase 4 |
| SCN-05 | `caution-raw-ip` | Raw IP alerts as `raw_ip` | 20 ms | Phase 4 |
| SCN-06 | `caution-high-entropy-domain` | Random-looking domain alerts | 20 ms | Phase 4 |
| SCN-07 | `caution-plaintext-known-host` | Plaintext to a listed host alerts with its URL | 20 ms | Phases 3, 4 |
| SCN-08 | `caution-unusual-port-known-process` | 30 points stay quiet | 20 ms | Phase 4 |
| SCN-09 | `caution-unusual-port-new-process` | 55 points alert | 20 ms | Phase 4 |
| SCN-10 | `caution-new-tld-quiet` | 45 points stay quiet | 20 ms | Phase 4 |
| SCN-11 | `caution-threat-list` | Threat list alerts at 100 | 20 ms | Phase 4 |
| SCN-12 | `alert-unlisted-host` | Alert mode alerts on unlisted hosts only | 20 ms | Phase 4 |
| SCN-13 | `alert-dedupe-window` | One alert per window per host + process | 20 ms | Phase 4 |
| SCN-14 | `alert-acknowledged` | Acknowledged alert stays silent | 20 ms | Phase 4 |
| SCN-15 | `counters-exact` | Exact counters per host and per process | 20 ms | Phases 3, 4 |
| SCN-16 | `hostname-unresolved` | ECH and nameless flows tracked and flagged | 20 ms | Phases 3, 4 |
| SCN-17 | `module-signal-scored` | A module signal lifts the score and names the alert | 20 ms | Phase 4 |
| SCN-18 | `daemon-hibernate-capped` | Hibernation capped, alerting, recording nothing | 20 ms | Phase 5 |
| SCN-19 | `daemon-wakeup-and-reset` | Wakeup resumes; reset keeps history | 20 ms | Phase 5 |
| SCN-20 | `restart_keeps_state` (new file) | Hosts, counters, baseline and mode survive a daemon restart on the same SQLite files | 50 ms | Phase 5 |
| SCN-21 | `storage_outage_and_replay` (new file) | State store down mid-run: buffer, drops counted, replay in order | 30 ms | Phases 2, 5 |
| SCN-22 | `sink_outage_spools` (new file) | Event sink down: spool, then replay; other sinks unaffected | 30 ms | Phases 2, 5 |
| SCN-23 | `module_panics_mid_run` (new file) | A test module panics; it is switched off, health degraded, the rest keeps going | 20 ms | Phase 5 |
| SCN-24 | `config_reload_mid_run` (new file) | Policy scores changed by reload apply from the next flow | 20 ms | Phase 5 |
| SCN-25 | `profiles_are_isolated` (new file) | A host learned in `work` is unlisted in `home` | 20 ms | Phase 4 |
| SCN-26 | `runner_rejects_bad_scenarios` | The runner refuses unknown keys and bad times with the file and line | < 10 ms | Phase 4 |

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
| Privileged sensor conformance | `pcap_sensor_conforms` and the native sensors on each OS; Linux kernel matrix | < 2 h |
| End-to-end | `tests/e2e/` on installed packages | 1–2 days with the release checklist |
| Fuzzing | `fuzz/` targets, 30 min each | < 2 h |
| Performance, soak, volume | 1,000 connections/s; 24 h soak; 10M events | Before release |
| UI browser tests | Vitest, Playwright, visual, `tauri-driver` | < 15 min (when the UI exists) |
| Live smoke | SMK-L1 – L6 against a running daemon | < 10 s |
