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
