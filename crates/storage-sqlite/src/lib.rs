//! SQLite backend (default). Provides both a [`StateStore`] and an [`EventSink`].
//!
//! Options: `path` (required) — database file. Schema lives in `migrations/`; `migrate` applies
//! the missing ones and refuses a database newer than this build. The file is opened on first use
//! in WAL mode.

mod db;
mod sink;
mod state;

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use scribe_core::Clock;

use crate::db::Db;

use scribe_storage_api::{
    required_option, AlertState, BackendOptions, Baseline, BaselineEntry, BoxFuture, EventQuery,
    EventSink, Health, Host, HostDelta, HostId, HostQuery, ModuleState, Page, Result, SinkCaps,
    StateStore, StorageFactory, StoreCaps, StoredEvent,
};

pub const KIND: &str = "sqlite";

/// Migration `n` (1-based) brings the schema to version `n`; the list ends at
/// [`scribe_storage_api::SCHEMA_VERSION`].
pub const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_modules.sql"),
];

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
    db: Db,
}

impl SqliteStore {
    pub fn from_options(options: &BackendOptions) -> Result<Self> {
        let path = required_option(options, KIND, "path")?;
        Ok(Self {
            db: Db::new(path.into()),
        })
    }

    /// Use `clock` for stored times (tests).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.db.clock = clock;
        self
    }

    pub fn path(&self) -> &Path {
        self.db.path()
    }

    /// The highest applied migration (0 for a new file).
    pub fn schema_version(&self) -> Result<u32> {
        self.db.version()
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
        Box::pin(async move { self.db.migrate().map(|_| ()) })
    }

    fn upsert_host<'a>(&'a self, delta: &'a HostDelta) -> BoxFuture<'a, Result<HostId>> {
        Box::pin(async move { self.db.with(|c| state::upsert_host(c, delta)) })
    }

    fn get_host<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Host>>> {
        Box::pin(async move { self.db.with(|c| state::get_host(c, name)) })
    }

    fn link_ip(&self, host: HostId, ip: IpAddr, ttl: Duration) -> BoxFuture<'_, Result<()>> {
        let now = self.db.now_ms();
        Box::pin(async move { self.db.with(|c| state::link_ip(c, host, ip, ttl, now)) })
    }

    fn list_hosts<'a>(&'a self, query: &'a HostQuery) -> BoxFuture<'a, Result<Page<Host>>> {
        Box::pin(async move { self.db.with(|c| state::list_hosts(c, query)) })
    }

    fn baseline<'a>(&'a self, profile: &'a str) -> BoxFuture<'a, Result<Baseline>> {
        Box::pin(async move { self.db.with(|c| state::baseline(c, profile)) })
    }

    fn add_to_baseline<'a>(
        &'a self,
        profile: &'a str,
        entry: &'a BaselineEntry,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.db.with(|c| state::add_to_baseline(c, profile, entry)) })
    }

    fn put_alert_state<'a>(&'a self, alert: &'a AlertState) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.db.with(|c| state::put_alert_state(c, alert)) })
    }

    fn get_alert_state<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<AlertState>>> {
        Box::pin(async move { self.db.with(|c| state::get_alert_state(c, key)) })
    }

    fn module_state<'a>(&'a self, module: &'a str) -> BoxFuture<'a, Result<ModuleState>> {
        Box::pin(async move { self.db.with(|c| state::module_state(c, module)) })
    }

    fn put_module_state<'a>(
        &'a self,
        module: &'a str,
        key: &'a str,
        value: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<()>> {
        let now = self.db.now_ms();
        Box::pin(async move {
            self.db
                .with(|c| state::put_module_state(c, module, key, value, now))
        })
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(async move { self.db.health() })
    }
}

pub struct SqliteSink {
    name: String,
    db: Db,
}

impl SqliteSink {
    pub fn from_options(name: &str, options: &BackendOptions) -> Result<Self> {
        let path = required_option(options, KIND, "path")?;
        Ok(Self {
            name: name.to_owned(),
            db: Db::new(path.into()),
        })
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.db.clock = clock;
        self
    }

    pub fn path(&self) -> &Path {
        self.db.path()
    }

    pub fn schema_version(&self) -> Result<u32> {
        self.db.version()
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
        Box::pin(async move { self.db.migrate().map(|_| ()) })
    }

    fn write_batch<'a>(&'a self, batch: &'a [StoredEvent]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.db.with(|c| sink::write_batch(c, batch)) })
    }

    fn query<'a>(&'a self, query: &'a EventQuery) -> BoxFuture<'a, Result<Page<StoredEvent>>> {
        Box::pin(async move { self.db.with_result(|c| sink::query(c, query)) })
    }

    /// Every batch is committed when `write_batch` returns, so there is nothing to flush.
    fn flush(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(async move { self.db.health() })
    }
}
