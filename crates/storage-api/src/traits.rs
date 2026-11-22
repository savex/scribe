use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use crate::{
    AlertState, Baseline, BaselineEntry, EventQuery, Health, Host, HostDelta, HostId, HostQuery,
    ModuleState, Page, Result, SinkCaps, StorageError, StoreCaps, StoredEvent,
};

/// Boxed future so the traits stay object-safe without extra crates.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Backend options from one `[storage.*]` config table, as flat key/value pairs.
pub type BackendOptions = HashMap<String, String>;

/// Transactional store for hosts, counters, baselines and alert state.
pub trait StateStore: Send + Sync {
    fn capabilities(&self) -> StoreCaps;
    /// Create or upgrade the schema. Must be idempotent.
    fn migrate(&self) -> BoxFuture<'_, Result<()>>;

    fn upsert_host<'a>(&'a self, delta: &'a HostDelta) -> BoxFuture<'a, Result<HostId>>;
    fn get_host<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Host>>>;
    fn link_ip(&self, host: HostId, ip: IpAddr, ttl: Duration) -> BoxFuture<'_, Result<()>>;
    fn list_hosts<'a>(&'a self, query: &'a HostQuery) -> BoxFuture<'a, Result<Page<Host>>>;

    fn baseline<'a>(&'a self, profile: &'a str) -> BoxFuture<'a, Result<Baseline>>;
    fn add_to_baseline<'a>(
        &'a self,
        profile: &'a str,
        entry: &'a BaselineEntry,
    ) -> BoxFuture<'a, Result<()>>;

    fn put_alert_state<'a>(&'a self, state: &'a AlertState) -> BoxFuture<'a, Result<()>>;
    fn get_alert_state<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<AlertState>>>;

    /// Every key a module stored; empty for a module that stored nothing.
    fn module_state<'a>(&'a self, module: &'a str) -> BoxFuture<'a, Result<ModuleState>>;
    /// Insert or replace one key of a module's state.
    fn put_module_state<'a>(
        &'a self,
        module: &'a str,
        key: &'a str,
        value: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<()>>;

    fn health(&self) -> BoxFuture<'_, Health>;
}

/// Append-only destination for flow, alert, audit, metric and module records.
pub trait EventSink: Send + Sync {
    fn name(&self) -> &str;
    fn capabilities(&self) -> SinkCaps;
    /// Create or upgrade the schema. Must be idempotent.
    fn migrate(&self) -> BoxFuture<'_, Result<()>>;
    fn write_batch<'a>(&'a self, batch: &'a [StoredEvent]) -> BoxFuture<'a, Result<()>>;

    /// Write-only sinks keep this default.
    fn query<'a>(&'a self, _query: &'a EventQuery) -> BoxFuture<'a, Result<Page<StoredEvent>>> {
        Box::pin(async { Err(StorageError::Unsupported("query")) })
    }

    fn flush(&self) -> BoxFuture<'_, Result<()>>;
    fn health(&self) -> BoxFuture<'_, Health>;

    /// Delete events and metric samples older than `cutoff`; returns how many were removed. The
    /// storage manager calls it for sinks without native retention (`SinkCaps::native_retention`).
    fn delete_before(&self, _cutoff: SystemTime) -> BoxFuture<'_, Result<u64>> {
        Box::pin(async { Err(StorageError::Unsupported("delete_before")) })
    }
}

/// Entry point of a storage backend. A backend may provide a state store, a sink, or both.
pub trait StorageFactory: Send + Sync {
    /// Value of `kind = "..."` in config.
    fn kind(&self) -> &'static str;
    /// `None` if this backend cannot act as a state store.
    fn build_state(&self, options: &BackendOptions) -> Option<Result<Box<dyn StateStore>>>;
    /// `None` if this backend cannot act as an event sink.
    fn build_sink(
        &self,
        name: &str,
        options: &BackendOptions,
    ) -> Option<Result<Box<dyn EventSink>>>;
}

/// Placeholder future for backend methods that are not written yet.
pub fn not_implemented<'a, T: Send + 'a>(op: &'static str) -> BoxFuture<'a, Result<T>> {
    Box::pin(async move { Err(StorageError::NotImplemented(op)) })
}

/// Read a required option, or fail with a config error naming the backend.
pub fn required_option<'a>(
    options: &'a BackendOptions,
    backend: &str,
    key: &str,
) -> Result<&'a str> {
    options
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| StorageError::Config(format!("{backend}: missing required option '{key}'")))
}
