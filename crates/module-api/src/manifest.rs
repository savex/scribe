//! What a module declares about itself.

/// Whether an API call only reads or changes something (specs 6.3: read vs control).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Control,
}

/// One call of the module's API service. Calls that aren't declared are refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub name: &'static str,
    pub access: Access,
}

/// A record kind the module emits, e.g. `url.request` with payload layout version 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordKind {
    pub name: &'static str,
    pub schema: u32,
}

/// Privileges a module needs, met only through the sensors' probe host (specs 7.4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Privilege {
    Bpf,
    Perfmon,
    EtwProvider(&'static str),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Needs {
    /// Payload bytes past the ClientHello / `Host` header.
    pub payload: bool,
    pub privileges: Vec<Privilege>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Lowercase id: `[a-z][a-z0-9_]*`; also the config section name and the prefix of every
    /// record kind and metric name.
    pub id: &'static str,
    pub version: u32,
    pub description: &'static str,
    pub records: Vec<RecordKind>,
    pub metrics: Vec<&'static str>,
    pub calls: Vec<Call>,
    pub needs: Needs,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("module manifest '{id}': {message}")]
pub struct ManifestError {
    pub id: String,
    pub message: String,
}

impl Manifest {
    pub fn new(id: &'static str, version: u32, description: &'static str) -> Self {
        Self {
            id,
            version,
            description,
            records: Vec::new(),
            metrics: Vec::new(),
            calls: Vec::new(),
            needs: Needs::default(),
        }
    }

    pub fn record(&self, name: &str) -> Option<&RecordKind> {
        self.records.iter().find(|r| r.name == name)
    }

    pub fn call(&self, name: &str) -> Option<&Call> {
        self.calls.iter().find(|c| c.name == name)
    }

    /// Check the naming rules.
    pub fn validate(&self) -> Result<(), ManifestError> {
        let fail = |message: String| {
            Err(ManifestError {
                id: self.id.into(),
                message,
            })
        };
        if !is_identifier(self.id) {
            return fail("id must match [a-z][a-z0-9_]*".into());
        }
        if self.version == 0 {
            return fail("version must be at least 1".into());
        }
        let prefix = format!("{}.", self.id);
        let mut seen = std::collections::HashSet::new();
        for name in self
            .records
            .iter()
            .map(|r| r.name)
            .chain(self.metrics.iter().copied())
        {
            match name.strip_prefix(&prefix) {
                Some(rest) if is_identifier(rest) => {}
                _ => return fail(format!("'{name}' must be named '{prefix}<name>'")),
            }
            if !seen.insert(name) {
                return fail(format!("'{name}' is declared twice"));
            }
        }
        if let Some(r) = self.records.iter().find(|r| r.schema == 0) {
            return fail(format!(
                "record kind '{}' needs a schema version >= 1",
                r.name
            ));
        }
        let mut calls = std::collections::HashSet::new();
        for call in &self.calls {
            if !is_identifier(call.name) {
                return fail(format!("call '{}' must match [a-z][a-z0-9_]*", call.name));
            }
            if !calls.insert(call.name) {
                return fail(format!("call '{}' is declared twice", call.name));
            }
        }
        Ok(())
    }
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
}
