use std::collections::BTreeMap;

use scribe_storage_api::{EventSink, Result, StateStore, StorageError, StorageFactory};

use crate::{BackendConfig, SinkConfig};

/// Maps `kind` names from config to backend factories.
#[derive(Default)]
pub struct Registry {
    factories: BTreeMap<&'static str, Box<dyn StorageFactory>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registry with every backend enabled through Cargo features.
    pub fn with_builtin() -> Self {
        #[allow(unused_mut)]
        let mut registry = Self::new();
        #[cfg(feature = "sqlite")]
        registry.register(Box::new(scribe_storage_sqlite::SqliteFactory));
        #[cfg(feature = "postgres")]
        registry.register(Box::new(scribe_storage_postgres::PostgresFactory));
        registry
    }

    pub fn register(&mut self, factory: Box<dyn StorageFactory>) {
        self.factories.insert(factory.kind(), factory);
    }

    pub fn kinds(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.factories.keys().copied()
    }

    pub fn build_state(&self, config: &BackendConfig) -> Result<Box<dyn StateStore>> {
        self.factory(&config.kind)?
            .build_state(&config.options)
            .unwrap_or_else(|| {
                Err(StorageError::Config(format!(
                    "'{}' cannot be used as state store",
                    config.kind
                )))
            })
    }

    pub fn build_sink(&self, config: &SinkConfig) -> Result<Box<dyn EventSink>> {
        let kind = &config.backend.kind;
        self.factory(kind)?
            .build_sink(&config.name, &config.backend.options)
            .unwrap_or_else(|| {
                Err(StorageError::Config(format!(
                    "'{kind}' cannot be used as event sink"
                )))
            })
    }

    fn factory(&self, kind: &str) -> Result<&dyn StorageFactory> {
        self.factories.get(kind).map(|f| f.as_ref()).ok_or_else(|| {
            let known: Vec<_> = self.kinds().collect();
            StorageError::Config(format!(
                "unknown storage kind '{kind}' (built with: {})",
                known.join(", ")
            ))
        })
    }
}
