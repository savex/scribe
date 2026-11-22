//! Functional tests for `scribe_module_api` (moved from `src/config.rs`).

use scribe_module_api::*;
use serde::Deserialize;
use std::ops::Range;

#[derive(Debug, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct UrlSection {
    query: Option<String>,
    max: u32,
}

fn line_of(text: &str, span: &Range<usize>) -> usize {
    text[..span.start].matches('\n').count() + 1
}

#[test]
fn reads_its_own_section() {
    let text = "mode = \"learn\"\n[modules]\nenabled = [\"url\"]\n[modules.url]\nquery = \"strip\"\nmax = 3\n";
    let got: UrlSection = ConfigDoc::new(text).section("url").unwrap();
    assert_eq!(
        got,
        UrlSection {
            query: Some("strip".into()),
            max: 3
        }
    );
}

#[test]
fn a_missing_section_is_the_default() {
    for text in [
        "",
        "  \n",
        "mode = \"learn\"\n",
        "[modules]\nenabled = []\n",
    ] {
        let got: UrlSection = ConfigDoc::new(text).section("url").unwrap();
        assert_eq!(got, UrlSection::default(), "{text:?}");
    }
}

#[test]
fn errors_keep_their_line() {
    let text = "mode = \"learn\"\n\n[modules.url]\nquery = \"strip\"\nmaximum = 3\n";
    let err = ConfigDoc::new(text)
        .section::<UrlSection>("url")
        .unwrap_err();
    assert!(err.message.contains("unknown field `maximum`"), "{err}");
    assert_eq!(line_of(text, err.span.as_ref().unwrap()), 5);

    let text = "[modules.url]\n\nmax = \"three\"\n";
    let err = ConfigDoc::new(text)
        .section::<UrlSection>("url")
        .unwrap_err();
    assert!(err.message.contains("invalid type"), "{err}");
    assert_eq!(line_of(text, err.span.as_ref().unwrap()), 3);
}

#[test]
fn rejects_sections_that_are_not_tables() {
    let text = "modules = 3\n";
    let err = ConfigDoc::new(text)
        .section::<UrlSection>("url")
        .unwrap_err();
    assert!(err.message.contains("`modules` must be a table"));
    let text = "[modules]\nurl = 3\n";
    let err = ConfigDoc::new(text)
        .section::<UrlSection>("url")
        .unwrap_err();
    assert!(err.message.contains("`modules.url` must be a table"));
    assert_eq!(line_of(text, err.span.as_ref().unwrap()), 2);
}

#[test]
fn reports_toml_syntax_errors() {
    let err = ConfigDoc::new("[modules.url\n")
        .section::<UrlSection>("url")
        .unwrap_err();
    assert!(err.span.is_some());
}

#[test]
fn reads_values_outside_the_section() {
    let text = "[privacy]\nurl_query = \"strip\"\n[log]\nlevel = 3\n";
    let doc = ConfigDoc::new(text);
    let got: Option<String> = doc.get(&["privacy", "url_query"]).unwrap();
    assert_eq!(got.as_deref(), Some("strip"));
    assert_eq!(doc.get::<String>(&["privacy", "other"]).unwrap(), None);
    assert_eq!(doc.get::<String>(&["nope", "url_query"]).unwrap(), None);
    assert_eq!(doc.get::<String>(&[]).unwrap(), None);
    assert_eq!(ConfigDoc::new("").get::<String>(&["a"]).unwrap(), None);
    let err = doc.get::<String>(&["log", "level"]).unwrap_err();
    assert_eq!(line_of(text, err.span.as_ref().unwrap()), 4);
}

#[test]
fn finds_spans_of_keys() {
    let text = "[modules.url]\nquery = \"strip\"\n";
    let doc = ConfigDoc::new(text);
    let span = doc.span_of(&["modules", "url", "query"]).unwrap();
    assert_eq!(&text[span], "\"strip\"");
    assert!(doc.span_of(&["modules", "url", "nope"]).is_none());
    assert!(doc
        .span_of(&["modules", "url", "query", "deeper"])
        .is_none());
    assert!(doc.span_of(&[]).is_none());
    assert_eq!(doc.text(), text);
}
