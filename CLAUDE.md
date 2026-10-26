# scribe

Cross-platform tracker of outgoing connections (Rust workspace). Overview in `readme.md`;
plan, diagrams, test approach and status in `workfiles/`.

All agreed assumptions and config values (modes, storage, enrichment, versioning, CI, test data)
are in the `scribe-conventions` skill: `.claude/skills/scribe-conventions/SKILL.md`.
Read it before changing a module, config, migration, workflow or test, and update it in the same
commit when a decision changes.

## Rules

- Minimum Rust is 1.70: no language or std features newer than that; check new dependencies' `rust-version`.
- Before committing: `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
  `cargo test --workspace --all-features`.
- `testdata/pcap/` and `fuzz/corpus/` are generated: edit `crates/test-support/src/fixtures.rs` and run
  `cargo run -p scribe-test-support --bin gen-fixtures`. Never edit them by hand.
- Released schema snapshots in `testdata/db/` are never edited; add a new version instead (`testdata/db/build.sh`).
- New storage backends must pass `scribe-storage-conformance`; new sensors must pass `scribe-sensor-conformance`.
- Production code reads time through `scribe_core::Clock`.
- Test data uses documentation address ranges and `example.com` / `example.net` names only; never real user traffic.
- Versions come from `v*` git tags; don't edit the `Cargo.toml` version by hand, use `scripts/version.sh` or the
  Bump version workflow.
