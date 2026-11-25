//! PostgreSQL backend (phase 12). The [`EventSink`] is implemented (plan option 12C: the fleet
//! history of UC-9); the [`StateStore`] is not yet and reports so.
//!
//! Options: `url` (required) — connection string without password; `credentials` — secret
//! reference holding the password; `schema` — tables in this schema instead of `public`.
//! TLS with full certificate checks for any server not on this machine (see `conn`). Schema
//! lives in `migrations/`.

mod conn;
mod sink;

pub use conn::Settings;

use std::net::IpAddr;
use std::time::Duration;

use scribe_storage_api::{
    not_implemented, required_option, AlertState, BackendOptions, Baseline, BaselineEntry,
    BoxFuture, EventQuery, EventSink, Health, Host, HostDelta, HostId, HostQuery, ModuleState,
    Page, Result, SinkCaps, StateStore, StorageFactory, StoreCaps, StoredEvent,
};

pub const KIND: &str = "postgres";

/// Migration `n` (1-based) brings the schema to version `n`; the list ends at
/// [`scribe_storage_api::SCHEMA_VERSION`].
pub const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_modules.sql"),
    include_str!("../migrations/0003_processes.sql"),
    include_str!("../migrations/0004_hours.sql"),
];

pub struct PostgresFactory;

impl StorageFactory for PostgresFactory {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn build_state(&self, options: &BackendOptions) -> Option<Result<Box<dyn StateStore>>> {
        Some(PostgresStore::from_options(options).map(|s| Box::new(s) as Box<dyn StateStore>))
    }

    fn build_sink(
        &self,
        name: &str,
        options: &BackendOptions,
    ) -> Option<Result<Box<dyn EventSink>>> {
        Some(PostgresSink::from_options(name, options).map(|s| Box::new(s) as Box<dyn EventSink>))
    }
}

pub struct PostgresStore {
    url: String,
}

impl PostgresStore {
    pub fn from_options(options: &BackendOptions) -> Result<Self> {
        let url = required_option(options, KIND, "url")?;
        Ok(Self {
            url: url.to_owned(),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

impl StateStore for PostgresStore {
    fn capabilities(&self) -> StoreCaps {
        StoreCaps {
            transactions: true,
            full_text_search: true,
        }
    }

    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        not_implemented("postgres: migrate")
    }

    fn upsert_host<'a>(&'a self, _delta: &'a HostDelta) -> BoxFuture<'a, Result<HostId>> {
        not_implemented("postgres: upsert_host")
    }

    fn get_host<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<Option<Host>>> {
        not_implemented("postgres: get_host")
    }

    fn link_ip(&self, _host: HostId, _ip: IpAddr, _ttl: Duration) -> BoxFuture<'_, Result<()>> {
        not_implemented("postgres: link_ip")
    }

    fn list_hosts<'a>(&'a self, _query: &'a HostQuery) -> BoxFuture<'a, Result<Page<Host>>> {
        not_implemented("postgres: list_hosts")
    }

    fn baseline<'a>(&'a self, _profile: &'a str) -> BoxFuture<'a, Result<Baseline>> {
        not_implemented("postgres: baseline")
    }

    fn add_to_baseline<'a>(
        &'a self,
        _profile: &'a str,
        _entry: &'a BaselineEntry,
    ) -> BoxFuture<'a, Result<()>> {
        not_implemented("postgres: add_to_baseline")
    }

    fn remove_from_baseline<'a>(
        &'a self,
        _profile: &'a str,
        _host: &'a str,
    ) -> BoxFuture<'a, Result<bool>> {
        not_implemented("postgres: remove_from_baseline")
    }

    fn put_alert_state<'a>(&'a self, _state: &'a AlertState) -> BoxFuture<'a, Result<()>> {
        not_implemented("postgres: put_alert_state")
    }

    fn get_alert_state<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<Option<AlertState>>> {
        not_implemented("postgres: get_alert_state")
    }

    fn alert_states(&self) -> BoxFuture<'_, Result<Vec<AlertState>>> {
        not_implemented("postgres: alert_states")
    }

    fn module_state<'a>(&'a self, _module: &'a str) -> BoxFuture<'a, Result<ModuleState>> {
        not_implemented("postgres: module_state")
    }

    fn put_module_state<'a>(
        &'a self,
        _module: &'a str,
        _key: &'a str,
        _value: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<()>> {
        not_implemented("postgres: put_module_state")
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(async {
            Health::Down(
                "postgres as the state store is not implemented yet; use it as an event sink"
                    .into(),
            )
        })
    }
}

pub struct PostgresSink {
    name: String,
    url: String,
    conn: sink::Connection,
}

impl PostgresSink {
    pub fn from_options(name: &str, options: &BackendOptions) -> Result<Self> {
        let url = required_option(options, KIND, "url")?;
        Ok(Self {
            name: name.to_owned(),
            url: url.to_owned(),
            conn: sink::Connection::new(Settings::from_options(options)?),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether the connection uses TLS (always for a server on another machine).
    pub fn uses_tls(&self) -> bool {
        self.conn.settings().uses_tls()
    }
}

impl EventSink for PostgresSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> SinkCaps {
        SinkCaps {
            queryable: true,
            native_retention: false,
            max_batch: 5000,
        }
    }

    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(self.conn.migrate())
    }

    fn delete_before(&self, cutoff: std::time::SystemTime) -> BoxFuture<'_, Result<u64>> {
        Box::pin(self.conn.delete_before(cutoff))
    }

    fn write_batch<'a>(&'a self, batch: &'a [StoredEvent]) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.conn.write(batch.to_vec()))
    }

    fn query<'a>(&'a self, query: &'a EventQuery) -> BoxFuture<'a, Result<Page<StoredEvent>>> {
        Box::pin(self.conn.query(query.clone()))
    }

    fn flush(&self) -> BoxFuture<'_, Result<()>> {
        // Every write is committed when it returns.
        Box::pin(async { Ok(()) })
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(self.conn.health())
    }
}
