//! SQLite backend (default). Provides both a [`StateStore`] and an [`EventSink`].
//!
//! Options: `path` (required) — database file. Schema lives in `migrations/`; `migrate` applies
//! the missing ones and refuses a database newer than this build. The file is opened on first use
//! in WAL mode, on a worker thread of its own, so async callers never block on SQLite.

mod db;
mod sink;
mod state;

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use scribe_core::Clock;

use crate::db::Db;

use scribe_storage_api::{
    required_option, AlertState, BackendOptions, Baseline, BaselineEntry, BoxFuture, EventQuery,
    EventSink, Health, Host, HostDelta, HostHour, HostId, HostQuery, ModuleState, Page,
    ProcessHost, Result, SinkCaps, StateStore, StorageFactory, StoreCaps, StoredEvent,
};

pub const KIND: &str = "sqlite";

/// Migration `n` (1-based) brings the schema to version `n`; the list ends at
/// [`scribe_storage_api::SCHEMA_VERSION`].
pub const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_modules.sql"),
    include_str!("../migrations/0003_processes.sql"),
    include_str!("../migrations/0004_hours.sql"),
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
        self.db.version().wait()
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
        let reply = self.db.migrate();
        Box::pin(async move { reply.await.map(|_| ()) })
    }

    fn upsert_host<'a>(&'a self, delta: &'a HostDelta) -> BoxFuture<'a, Result<HostId>> {
        let delta = delta.clone();
        Box::pin(self.db.with(move |c| {
            // Host and process + host counters change together or not at all.
            let tx = c.transaction()?;
            let id = state::upsert_host(&tx, &delta)?;
            tx.commit()?;
            Ok(id)
        }))
    }

    fn get_host<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Host>>> {
        let name = name.to_owned();
        Box::pin(self.db.with(move |c| state::get_host(c, &name)))
    }

    fn link_ip(&self, host: HostId, ip: IpAddr, ttl: Duration) -> BoxFuture<'_, Result<()>> {
        let now = self.db.now_ms();
        Box::pin(self.db.with(move |c| state::link_ip(c, host, ip, ttl, now)))
    }

    fn list_hosts<'a>(&'a self, query: &'a HostQuery) -> BoxFuture<'a, Result<Page<Host>>> {
        let query = query.clone();
        Box::pin(self.db.with(move |c| state::list_hosts(c, &query)))
    }

    fn process_hosts<'a>(
        &'a self,
        process: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Vec<ProcessHost>>> {
        let process = process.map(str::to_owned);
        Box::pin(
            self.db
                .with(move |c| state::process_hosts(c, process.as_deref())),
        )
    }

    fn host_hours<'a>(
        &'a self,
        host: &'a str,
        since: SystemTime,
    ) -> BoxFuture<'a, Result<Vec<HostHour>>> {
        let host = host.to_owned();
        Box::pin(self.db.with(move |c| state::host_hours(c, &host, since)))
    }

    fn prune_host_hours(&self, before: SystemTime) -> BoxFuture<'_, Result<u64>> {
        Box::pin(self.db.with(move |c| state::prune_host_hours(c, before)))
    }

    fn baseline<'a>(&'a self, profile: &'a str) -> BoxFuture<'a, Result<Baseline>> {
        let profile = profile.to_owned();
        Box::pin(self.db.with(move |c| state::baseline(c, &profile)))
    }

    fn add_to_baseline<'a>(
        &'a self,
        profile: &'a str,
        entry: &'a BaselineEntry,
    ) -> BoxFuture<'a, Result<()>> {
        let (profile, entry) = (profile.to_owned(), entry.clone());
        Box::pin(
            self.db
                .with(move |c| state::add_to_baseline(c, &profile, &entry)),
        )
    }

    fn remove_from_baseline<'a>(
        &'a self,
        profile: &'a str,
        host: &'a str,
    ) -> BoxFuture<'a, Result<bool>> {
        let (profile, host) = (profile.to_owned(), host.to_owned());
        Box::pin(
            self.db
                .with(move |c| state::remove_from_baseline(c, &profile, &host)),
        )
    }

    fn put_alert_state<'a>(&'a self, alert: &'a AlertState) -> BoxFuture<'a, Result<()>> {
        let alert = alert.clone();
        Box::pin(self.db.with(move |c| state::put_alert_state(c, &alert)))
    }

    fn get_alert_state<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<AlertState>>> {
        let key = key.to_owned();
        Box::pin(self.db.with(move |c| state::get_alert_state(c, &key)))
    }

    fn alert_states(&self) -> BoxFuture<'_, Result<Vec<AlertState>>> {
        Box::pin(self.db.with(|c| state::alert_states(c)))
    }

    fn module_state<'a>(&'a self, module: &'a str) -> BoxFuture<'a, Result<ModuleState>> {
        let module = module.to_owned();
        Box::pin(self.db.with(move |c| state::module_state(c, &module)))
    }

    fn put_module_state<'a>(
        &'a self,
        module: &'a str,
        key: &'a str,
        value: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<()>> {
        let now = self.db.now_ms();
        let (module, key, value) = (module.to_owned(), key.to_owned(), value.clone());
        Box::pin(
            self.db
                .with(move |c| state::put_module_state(c, &module, &key, &value, now)),
        )
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(self.db.health())
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
        self.db.version().wait()
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
        let reply = self.db.migrate();
        Box::pin(async move { reply.await.map(|_| ()) })
    }

    fn write_batch<'a>(&'a self, batch: &'a [StoredEvent]) -> BoxFuture<'a, Result<()>> {
        let batch = batch.to_vec();
        Box::pin(self.db.with(move |c| sink::write_batch(c, &batch)))
    }

    fn query<'a>(&'a self, query: &'a EventQuery) -> BoxFuture<'a, Result<Page<StoredEvent>>> {
        let query = query.clone();
        Box::pin(self.db.run(move |c| sink::query(c, &query)))
    }

    fn delete_before(&self, cutoff: std::time::SystemTime) -> BoxFuture<'_, Result<u64>> {
        let cutoff = scribe_storage_api::codec::to_millis(cutoff);
        Box::pin(self.db.with(move |c| sink::delete_before(c, cutoff)))
    }

    /// Every batch is committed when `write_batch` returns, so there is nothing to flush.
    fn flush(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(self.db.health())
    }
}
