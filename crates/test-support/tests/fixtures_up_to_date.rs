use scribe_test_support::{fixtures, repo_root};

mod smoke {
    use super::*;

    #[test]
    fn committed_fixtures_match_generator() {
        let stale = fixtures::stale(&repo_root());
        assert!(
            stale.is_empty(),
            "stale fixtures {stale:?}; run `cargo run -p scribe-test-support --bin gen-fixtures`"
        );
    }
}

mod functional {
    use super::*;

    #[test]
    fn fixture_names_are_unique() {
        let mut names: Vec<_> = fixtures::all().iter().map(|f| f.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
    }
}
