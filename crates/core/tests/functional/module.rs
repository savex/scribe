//! Functional tests for `scribe_core::module` (moved from `src/module.rs`).

use scribe_core::module::*;
use serde_json::json;

#[test]
fn notes_keep_one_value_per_module() {
    let mut notes = Notes::new();
    assert!(notes.is_empty());
    notes.insert("url", json!("http://plain.example.com/a"));
    notes.insert("url", json!("http://plain.example.com/b"));
    notes.insert("other", json!({ "n": 1 }));
    assert_eq!(notes.len(), 2);
    assert_eq!(notes.get_str("url"), Some("http://plain.example.com/b"));
    assert_eq!(notes.get_str("other"), None);
    assert_eq!(notes.get("missing"), None);
    let keys: Vec<_> = notes.iter().map(|(k, _)| k).collect();
    assert_eq!(keys, ["other", "url"]);
}

#[test]
fn merge_prefers_the_newer_note() {
    let mut a = Notes::new();
    a.insert("url", json!("old"));
    let mut b = Notes::new();
    b.insert("url", json!("new"));
    b.insert("x", json!(true));
    a.merge(b);
    assert_eq!(a.get_str("url"), Some("new"));
    assert_eq!(a.len(), 2);
}

#[test]
fn notes_serialize_as_a_plain_object() {
    let mut notes = Notes::new();
    notes.insert("url", json!("http://plain.example.com/"));
    let text = serde_json::to_string(&notes).unwrap();
    assert_eq!(text, r#"{"url":"http://plain.example.com/"}"#);
    let back: Notes = serde_json::from_str(&text).unwrap();
    assert_eq!(back, notes);
}
