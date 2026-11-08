//! SQLite backend (default). Provides both a [`StateStore`] and an [`EventSink`].
//!
//! Options: `path` (required) — database file. Schema lives in `migrations/`.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use scribe_storage_api::{
    not_implemented, required_option, AlertState, BackendOptions, Baseline, BaselineEntry,
    BoxFuture, EventQuery, EventSink, Health, Host, HostDelta, HostId, HostQuery, ModuleState,
    Page, Result, SinkCaps, StateStore, StorageFactory, StoreCaps, StoredEvent,
};

pub const KIND: &str = "sqlite";

pub const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_init.sql")];

pub struct SqliteFactory;

impl StorageFactory for SqliteFactory {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn build_state(&self, options: &BackendOptions) -> Option<Result<Box<dyn StateStore>>> {
        Some(SqliteStore::from_options(options).map(|s| Box::new(s) as Box<dyn StateStore>))
    }

    fn build_sink(
        &self,
        name: &str,
        options: &BackendOptions,
    ) -> Option<Result<Box<dyn EventSink>>> {
        Some(SqliteSink::from_options(name, options).map(|s| Box::new(s) as Box<dyn EventSink>))
    }
}

pub struct SqliteStore {
    path: PathBuf,
}

impl SqliteStore {
    pub fn from_options(options: &BackendOptions) -> Result<Self> {
        let path = required_option(options, KIND, "path")?;
        Ok(Self { path: path.into() })
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl StateStore for SqliteStore {
    fn capabilities(&self) -> StoreCaps {
        StoreCaps {
            transactions: true,
            full_text_search: false,
        }
    }

    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        not_implemented("sqlite: migrate")
    }

    fn upsert_host<'a>(&'a self, _delta: &'a HostDelta) -> BoxFuture<'a, Result<HostId>> {
        not_implemented("sqlite: upsert_host")
    }

    fn get_host<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<Option<Host>>> {
        not_implemented("sqlite: get_host")
    }

    fn link_ip(&self, _host: HostId, _ip: IpAddr, _ttl: Duration) -> BoxFuture<'_, Result<()>> {
        not_implemented("sqlite: link_ip")
    }

    fn list_hosts<'a>(&'a self, _query: &'a HostQuery) -> BoxFuture<'a, Result<Page<Host>>> {
        not_implemented("sqlite: list_hosts")
    }

    fn baseline<'a>(&'a self, _profile: &'a str) -> BoxFuture<'a, Result<Baseline>> {
        not_implemented("sqlite: baseline")
    }

    fn add_to_baseline<'a>(
        &'a self,
        _profile: &'a str,
        _entry: &'a BaselineEntry,
    ) -> BoxFuture<'a, Result<()>> {
        not_implemented("sqlite: add_to_baseline")
    }

    fn put_alert_state<'a>(&'a self, _state: &'a AlertState) -> BoxFuture<'a, Result<()>> {
        not_implemented("sqlite: put_alert_state")
    }

    fn get_alert_state<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<Option<AlertState>>> {
        not_implemented("sqlite: get_alert_state")
    }

    fn module_state<'a>(&'a self, _module: &'a str) -> BoxFuture<'a, Result<ModuleState>> {
        not_implemented("sqlite: module_state")
    }

    fn put_module_state<'a>(
        &'a self,
        _module: &'a str,
        _key: &'a str,
        _value: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<()>> {
        not_implemented("sqlite: put_module_state")
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(async { Health::Down("sqlite backend not implemented yet".into()) })
    }
}

pub struct SqliteSink {
    name: String,
    path: PathBuf,
}

impl SqliteSink {
    pub fn from_options(name: &str, options: &BackendOptions) -> Result<Self> {
        let path = required_option(options, KIND, "path")?;
        Ok(Self {
            name: name.to_owned(),
            path: path.into(),
        })
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl EventSink for SqliteSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> SinkCaps {
        SinkCaps {
            queryable: true,
            native_retention: false,
            max_batch: 1000,
        }
    }

    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        not_implemented("sqlite: migrate")
    }

    fn write_batch<'a>(&'a self, _batch: &'a [StoredEvent]) -> BoxFuture<'a, Result<()>> {
        not_implemented("sqlite: write_batch")
    }

    fn query<'a>(&'a self, _query: &'a EventQuery) -> BoxFuture<'a, Result<Page<StoredEvent>>> {
        not_implemented("sqlite: query")
    }

    fn flush(&self) -> BoxFuture<'_, Result<()>> {
        not_implemented("sqlite: flush")
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(async { Health::Down("sqlite backend not implemented yet".into()) })
    }
}
