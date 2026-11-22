use scribe_test_support::fixtures;

#[test]
fn fixture_names_are_unique() {
    let mut names: Vec<_> = fixtures::all().iter().map(|f| f.name).collect();
    let count = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), count);
}
