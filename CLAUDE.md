# scribe

Cross-platform tracker of outgoing connections (Rust workspace). Overview in `readme.md`;
plan, diagrams, test approach and status in `workfiles/`.

All agreed assumptions and config values (modes, storage, enrichment, versioning, CI, test data)
are in the `scribe-conventions` skill: `.claude/skills/scribe-conventions/SKILL.md`.
Read it before changing a module, config, migration, workflow or test, and update it in the same
commit when a decision changes.

## Rules

- Minimum Rust version follows the dependencies (currently 1.89, `rust-version` in `Cargo.toml`). Raise it only
  when a dependency needs it, in the same commit as that dependency, and record the reason in the conventions skill.
  Don't pin a crate to an old release just to avoid a raise.
- Every commit that changes behaviour, configuration, interfaces, tooling or documents adds a line to
  `changelog.md` under **Unreleased**.
- Before committing: `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
  `cargo nextest run --workspace --all-features` (or `cargo test`), `scripts/check-test-tags.sh`.
- Every test sits in exactly one tag module: `smoke::`, `functional::`, `integration::` or `scenario::`, and
  follows the isolation rules in `workfiles/test-list.md` (own temp dir, ports, clock; no global state).
  The fast run must stay under 120 s.
- `testdata/pcap/` and `fuzz/corpus/` are generated: edit `crates/test-support/src/fixtures.rs` and run
  `cargo run -p scribe-test-support --bin gen-fixtures`. Never edit them by hand.
- Released schema snapshots in `testdata/db/` are never edited; add a new version instead (`testdata/db/build.sh`).
- New storage backends must pass `scribe-storage-conformance`; new sensors must pass `scribe-sensor-conformance`;
  new modules must pass `scribe-module-conformance`. New functionality goes into a module (`crates/module-*`)
  rather than into `core`, `storage-api` or the daemon.
- Production code reads time through `scribe_core::Clock`.
- Test data uses documentation address ranges and `example.com` / `example.net` names only; never real user traffic.
- Versions come from `v*` git tags; don't edit the `Cargo.toml` version by hand, use `scripts/version.sh` or the
  Bump version workflow.
