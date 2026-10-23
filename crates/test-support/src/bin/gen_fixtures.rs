//! Regenerate `testdata/pcap/*` and `fuzz/corpus/*`.
//!
//! `cargo run -p scribe-test-support --bin gen-fixtures`          write files
//! `cargo run -p scribe-test-support --bin gen-fixtures -- --check` fail if any file is stale

use std::process::ExitCode;

use scribe_test_support::{fixtures, repo_root};

fn main() -> ExitCode {
    let root = repo_root();
    if std::env::args().any(|a| a == "--check") {
        let stale = fixtures::stale(&root);
        if stale.is_empty() {
            println!("fixtures up to date");
            return ExitCode::SUCCESS;
        }
        for path in stale {
            eprintln!("stale: {}", path.display());
        }
        return ExitCode::FAILURE;
    }
    match fixtures::write_all(&root) {
        Ok(count) => {
            println!("wrote {count} files under {}", root.display());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("gen-fixtures: {err}");
            ExitCode::FAILURE
        }
    }
}
