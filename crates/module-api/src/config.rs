//! A module's view of the config file. The module reads `[modules.<id>]` with serde; errors keep
//! their position in the file because the section is deserialized from the spanned document.

use std::ops::Range;

use serde::de::DeserializeOwned;
use toml::de::{DeTable, DeValue, ValueDeserializer};

/// The whole config file as text. Built by the daemon; empty for built-in defaults.
#[derive(Debug, Clone, Copy)]
pub struct ConfigDoc<'a> {
    text: &'a str,
}

/// A problem in a module's section; `span` is a byte range in the config text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct SectionError {
    pub message: String,
    pub span: Option<Range<usize>>,
}

impl SectionError {
    pub fn new(message: impl Into<String>, span: Option<Range<usize>>) -> Self {
        Self {
            message: message.into(),
            span,
        }
    }
}

impl<'a> ConfigDoc<'a> {
    pub fn new(text: &'a str) -> Self {
        Self { text }
    }

    pub fn text(&self) -> &'a str {
        self.text
    }

    /// Deserialize `[modules.<module>]` as `T`; a missing section gives `T::default()`.
    pub fn section<T: DeserializeOwned + Default>(&self, module: &str) -> Result<T, SectionError> {
        if self.text.trim().is_empty() {
            return Ok(T::default());
        }
        let root = DeTable::parse(self.text)
            .map_err(|e| SectionError::new(e.message().to_owned(), e.span()))?;
        let Some(modules) = root.get_ref().get("modules") else {
            return Ok(T::default());
        };
        let DeValue::Table(modules) = modules.get_ref() else {
            return Err(SectionError::new(
                "`modules` must be a table",
                Some(modules.span()),
            ));
        };
        let Some(section) = modules.get(module) else {
            return Ok(T::default());
        };
        if !matches!(section.get_ref(), DeValue::Table(_)) {
            return Err(SectionError::new(
                format!("`modules.{module}` must be a table"),
                Some(section.span()),
            ));
        }
        T::deserialize(ValueDeserializer::from(section.clone()))
            .map_err(|e| SectionError::new(e.message().to_owned(), e.span()))
    }

    /// Deserialize the value at a key path outside the module's section (e.g. a deprecated key it
    /// still honours); `None` when absent.
    pub fn get<T: DeserializeOwned>(&self, path: &[&str]) -> Result<Option<T>, SectionError> {
        if self.text.trim().is_empty() {
            return Ok(None);
        }
        let root = DeTable::parse(self.text)
            .map_err(|e| SectionError::new(e.message().to_owned(), e.span()))?;
        let Some((last, parents)) = path.split_last() else {
            return Ok(None);
        };
        let mut table = root.get_ref();
        for key in parents {
            match table.get(*key).map(|v| v.get_ref()) {
                Some(DeValue::Table(t)) => table = t,
                _ => return Ok(None),
            }
        }
        let Some(value) = table.get(*last) else {
            return Ok(None);
        };
        T::deserialize(ValueDeserializer::from(value.clone()))
            .map(Some)
            .map_err(|e| SectionError::new(e.message().to_owned(), e.span().or(Some(value.span()))))
    }

    /// The span of a key path like `modules.url.query`, for errors found after deserializing.
    pub fn span_of(&self, path: &[&str]) -> Option<Range<usize>> {
        let root = DeTable::parse(self.text).ok()?;
        let mut table = root.get_ref();
        let (last, parents) = path.split_last()?;
        for key in parents {
            match table.get(*key)?.get_ref() {
                DeValue::Table(t) => table = t,
                _ => return None,
            }
        }
        Some(table.get(*last)?.span())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

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
}
