//! PostgreSQL backend. Provides both a [`StateStore`] and an [`EventSink`].
//!
//! Options: `url` (required) — connection string without password;
//! `credentials` — secret reference (keychain / DPAPI / secret-service), resolved by the manager.
//! Schema lives in `migrations/`.

use std::net::IpAddr;
use std::time::Duration;

use scribe_storage_api::{
    not_implemented, required_option, AlertState, BackendOptions, Baseline, BaselineEntry,
    BoxFuture, EventQuery, EventSink, Health, Host, HostDelta, HostId, HostQuery, Page, Result,
    SinkCaps, StateStore, StorageFactory, StoreCaps, StoredEvent,
};

pub const KIND: &str = "postgres";

pub const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_init.sql")];

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
        Ok(Self { url: url.to_owned() })
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

impl StateStore for PostgresStore {
    fn capabilities(&self) -> StoreCaps {
        StoreCaps { transactions: true, full_text_search: true }
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

    fn put_alert_state<'a>(&'a self, _state: &'a AlertState) -> BoxFuture<'a, Result<()>> {
        not_implemented("postgres: put_alert_state")
    }

    fn get_alert_state<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<Option<AlertState>>> {
        not_implemented("postgres: get_alert_state")
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(async { Health::Down("postgres backend not implemented yet".into()) })
    }
}

pub struct PostgresSink {
    name: String,
    url: String,
}

impl PostgresSink {
    pub fn from_options(name: &str, options: &BackendOptions) -> Result<Self> {
        let url = required_option(options, KIND, "url")?;
        Ok(Self { name: name.to_owned(), url: url.to_owned() })
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

impl EventSink for PostgresSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> SinkCaps {
        SinkCaps { queryable: true, native_retention: false, max_batch: 5000 }
    }

    fn migrate(&self) -> BoxFuture<'_, Result<()>> {
        not_implemented("postgres: migrate")
    }

    fn write_batch<'a>(&'a self, _batch: &'a [StoredEvent]) -> BoxFuture<'a, Result<()>> {
        not_implemented("postgres: write_batch")
    }

    fn query<'a>(&'a self, _query: &'a EventQuery) -> BoxFuture<'a, Result<Page<StoredEvent>>> {
        not_implemented("postgres: query")
    }

    fn flush(&self) -> BoxFuture<'_, Result<()>> {
        not_implemented("postgres: flush")
    }

    fn health(&self) -> BoxFuture<'_, Health> {
        Box::pin(async { Health::Down("postgres backend not implemented yet".into()) })
    }
}
