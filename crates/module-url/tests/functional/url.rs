//! Functional tests for `scribe_module_url` (moved from `src/lib.rs`).

use scribe_module_api::{ConfigDoc, Module, SectionError};
use scribe_module_url::*;

fn query(text: &str) -> Result<Query, SectionError> {
    settings(&ConfigDoc::new(text)).map(|s| s.query)
}

#[test]
fn default_is_redact_values() {
    assert_eq!(query("").unwrap(), Query::RedactValues);
    assert_eq!(query("[modules.url]\n").unwrap(), Query::RedactValues);
}

#[test]
fn reads_the_new_key_and_the_deprecated_one() {
    assert_eq!(
        query("[modules.url]\nquery = \"strip\"\n").unwrap(),
        Query::Strip
    );
    assert_eq!(
        query("[privacy]\nurl_query = \"path_only\"\n").unwrap(),
        Query::PathOnly
    );
    let same = "[privacy]\nurl_query = \"hash\"\n[modules.url]\nquery = \"hash\"\n";
    assert_eq!(query(same).unwrap(), Query::Hash);
}

#[test]
fn conflicting_keys_are_an_error_at_the_old_key() {
    let text = "[privacy]\nurl_query = \"full\"\n[modules.url]\nquery = \"strip\"\n";
    let err = query(text).unwrap_err();
    assert!(err.message.contains("disagree"), "{err}");
    let span = err.span.unwrap();
    assert_eq!(&text[span], "\"full\"");
}

#[test]
fn reports_its_effective_settings() {
    let mut module = UrlModule::default();
    module
        .configure(&ConfigDoc::new("[privacy]\nurl_query = \"strip\"\n"))
        .unwrap();
    let table = module.effective_config().unwrap();
    assert_eq!(table["query"].as_str(), Some("strip"));
}

#[test]
fn names_match_the_config_values() {
    for q in [
        Query::Full,
        Query::RedactValues,
        Query::Strip,
        Query::PathOnly,
        Query::Hash,
    ] {
        let text = format!("[modules.url]\nquery = \"{}\"\n", q.name());
        assert_eq!(query(&text).unwrap(), q);
    }
}
