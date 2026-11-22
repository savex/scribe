//! Committed fixtures and fuzz seeds match the generator.

use scribe_test_support::{fixtures, repo_root};

#[test]
fn committed_fixtures_match_generator() {
    let stale = fixtures::stale(&repo_root());
    assert!(
        stale.is_empty(),
        "stale fixtures {stale:?}; run `cargo run -p scribe-test-support --bin gen-fixtures`"
    );
}
