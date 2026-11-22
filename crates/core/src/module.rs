//! Data produced by modules (see `scribe-module-api`). These types live in `core` so storage can
//! carry them without depending on the module API.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Values modules attach to a flow, keyed by module id (e.g. `"url"` → the request URL).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Notes(BTreeMap<String, Value>);

impl Notes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the note of `module`, replacing an earlier one.
    pub fn insert(&mut self, module: impl Into<String>, value: Value) {
        self.0.insert(module.into(), value);
    }

    pub fn get(&self, module: &str) -> Option<&Value> {
        self.0.get(module)
    }

    /// The note of `module` when it is a string.
    pub fn get_str(&self, module: &str) -> Option<&str> {
        self.get(module).and_then(Value::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Add every note of `other`; `other` wins on the same module.
    pub fn merge(&mut self, other: Notes) {
        self.0.extend(other.0);
    }
}

/// A module's own event, e.g. kind `url.request`. Kinds are always prefixed with the module id.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleRecord {
    pub ts: SystemTime,
    pub module: Cow<'static, str>,
    pub kind: Cow<'static, str>,
    /// Version of `payload`'s layout for this kind.
    pub schema: u32,
    pub host: Option<String>,
    pub payload: Value,
}

/// One time-series point, e.g. `kperf.tcp_retrans` with labels `{ "iface": "eth0" }`.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricSample {
    pub ts: SystemTime,
    pub module: Cow<'static, str>,
    pub name: Cow<'static, str>,
    pub labels: BTreeMap<String, String>,
    pub value: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    mod functional {
        use super::*;

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
    }
}
