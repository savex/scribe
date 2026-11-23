//! `MockApiServer`: the local API answered from a UI mock scenario (`ui/tests/mocks/api-scenarios/`)
//! over the real transport, so the CLI and the UI can be tested without a daemon, capture rights
//! or real traffic. Feature `mock-api`.
//!
//! A scenario holds the messages the read calls return (`status`, `hosts`, `alerts`,
//! `baseline`), may `extends` another file and `generate` many hosts. Control calls change the
//! mock's state the way scribed would (mode, acknowledgements, baseline, hibernation), without
//! access checks. `connect` (refused connections) and the `stream` / `timeline` sections are for the
//! UI's own harness and aren't played here.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use scribe_api::pb::scribe_server::Scribe;
use scribe_api::pb::{self, health_reply::Level};
use serde_json::Value;
use tokio::sync::oneshot;
use tokio_stream::Stream;
use tonic::{Request, Response, Status as RpcStatus};

type Reply<T> = Result<Response<T>, RpcStatus>;
type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, RpcStatus>> + Send>>;

/// What a scenario holds, as API messages.
#[derive(Debug, Clone, Default)]
pub struct Scenario {
    pub name: String,
    pub status: pb::Status,
    pub hosts: Vec<pb::Host>,
    pub alerts: Vec<pb::Alert>,
    pub baseline: pb::Baseline,
    /// The scenario expects connections to be refused (`daemon-down`).
    pub refuses_connections: bool,
}

fn merge(base: &mut Value, over: Value) {
    match (base, over) {
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(existing) if existing.is_object() && v.is_object() => merge(existing, v),
                    _ => {
                        b.insert(k, v);
                    }
                }
            }
        }
        (b, o) => *b = o,
    }
}

/// The file with `extends` applied (the extending file wins key by key).
fn load_merged(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut doc: Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(parent) = doc.get("extends").and_then(Value::as_str) {
        let mut base = load_merged(&path.with_file_name(parent))?;
        let own = std::mem::take(&mut doc);
        merge(&mut base, own);
        doc = base;
    }
    Ok(doc)
}

fn section<T: serde::de::DeserializeOwned + Default>(doc: &Value, key: &str) -> Result<T, String> {
    match doc.get(key) {
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| format!("{key}: {e}")),
        None => Ok(T::default()),
    }
}

/// `generate.hosts`: `count` hosts named by `name_pattern` (`{n}` = 1, 2, …), deterministic.
fn generated_hosts(spec: &Value) -> Vec<pb::Host> {
    let count = spec["count"].as_u64().unwrap_or(0);
    let pattern = spec["name_pattern"]
        .as_str()
        .unwrap_or("host-{n}.example.com");
    let ratio = spec["on_list_ratio"].as_f64().unwrap_or(0.0);
    let (min, max) = (
        spec.pointer("/conn_count/min")
            .and_then(Value::as_u64)
            .unwrap_or(1),
        spec.pointer("/conn_count/max")
            .and_then(Value::as_u64)
            .unwrap_or(1),
    );
    let mut state = spec["seed"].as_u64().unwrap_or(1).max(1);
    let mut next = move || {
        // xorshift64: the same hosts every run.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    (1..=count)
        .map(|n| {
            let r = next();
            pb::Host {
                name: pattern.replace("{n}", &n.to_string()),
                on_list: (r % 1000) as f64 / 1000.0 < ratio,
                conn_count: min + r % (max - min + 1).max(1),
                tls_seen: true,
                first_seen_ms: 1_700_000_000_000,
                last_seen_ms: 1_700_000_000_000,
                ..Default::default()
            }
        })
        .collect()
}

impl Scenario {
    /// Reads `path` (with `extends`) into API messages.
    pub fn load(path: &Path) -> Result<Self, String> {
        let doc = load_merged(path)?;
        let page: pb::HostPage = section(&doc, "hosts")?;
        let mut hosts = page.items;
        if let Some(spec) = doc.pointer("/generate/hosts") {
            hosts = generated_hosts(spec);
        }
        let alerts: pb::AlertPage = section(&doc, "alerts")?;
        Ok(Self {
            name: doc["scenario"].as_str().unwrap_or_default().to_owned(),
            status: section(&doc, "status")?,
            hosts,
            alerts: alerts.items,
            baseline: section(&doc, "baseline")?,
            refuses_connections: doc.get("connect").is_some(),
        })
    }

    /// `ui/tests/mocks/api-scenarios/<name>.json` under `repo`.
    pub fn named(repo: &Path, name: &str) -> Result<Self, String> {
        Self::load(&repo.join(format!("ui/tests/mocks/api-scenarios/{name}.json")))
    }
}

/// The scenario's state behind the service; control calls change it.
struct MockApi {
    state: Arc<Mutex<Scenario>>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

impl MockApi {
    fn with<T>(&self, f: impl FnOnce(&mut Scenario) -> T) -> T {
        f(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

fn page<T: Clone>(items: &[T], offset: u64, limit: u64) -> Vec<T> {
    let start = (offset as usize).min(items.len());
    let end = if limit == 0 {
        items.len()
    } else {
        (start + limit as usize).min(items.len())
    };
    items[start..end].to_vec()
}

#[tonic::async_trait]
impl Scribe for MockApi {
    async fn get_status(&self, _: Request<pb::StatusRequest>) -> Reply<pb::Status> {
        Ok(Response::new(self.with(|s| s.status.clone())))
    }

    async fn health(&self, _: Request<pb::HealthRequest>) -> Reply<pb::HealthReply> {
        Ok(Response::new(self.with(|s| {
            let reasons: Vec<String> = s.status.critical.iter().map(|c| c.detail.clone()).collect();
            let level = if s
                .status
                .critical
                .iter()
                .any(|c| c.kind == "sensor_detached")
            {
                Level::Unhealthy
            } else if reasons.is_empty() {
                Level::Healthy
            } else {
                Level::Degraded
            };
            pb::HealthReply {
                level: level as i32,
                reasons,
            }
        })))
    }

    async fn list_hosts(&self, r: Request<pb::ListHostsRequest>) -> Reply<pb::HostPage> {
        let r = r.into_inner();
        Ok(Response::new(self.with(|s| {
            let matching: Vec<pb::Host> = s
                .hosts
                .iter()
                .filter(|h| h.name.contains(&r.name_contains))
                .cloned()
                .collect();
            pb::HostPage {
                total: Some(matching.len() as u64),
                items: page(&matching, r.offset, r.limit),
            }
        })))
    }

    async fn list_host_hours(&self, r: Request<pb::ListHostHoursRequest>) -> Reply<pb::HostHours> {
        Ok(Response::new(pb::HostHours {
            host: r.into_inner().host,
            items: vec![],
        }))
    }

    async fn list_alerts(&self, r: Request<pb::ListAlertsRequest>) -> Reply<pb::AlertPage> {
        let r = r.into_inner();
        Ok(Response::new(self.with(|s| {
            let mut alerts = s.alerts.clone();
            alerts.sort_by_key(|a| a.id);
            alerts.retain(|a| r.since_ms.is_none_or(|since| a.ts_ms >= since));
            pb::AlertPage {
                total: Some(alerts.len() as u64),
                items: page(&alerts, r.offset, r.limit),
            }
        })))
    }

    type WatchAlertsStream = BoxStream<pb::Alert>;

    async fn watch_alerts(
        &self,
        _: Request<pb::WatchAlertsRequest>,
    ) -> Reply<Self::WatchAlertsStream> {
        Ok(Response::new(Box::pin(tokio_stream::pending())))
    }

    async fn get_baseline(&self, _: Request<pb::GetBaselineRequest>) -> Reply<pb::Baseline> {
        Ok(Response::new(self.with(|s| s.baseline.clone())))
    }

    type ExportStream = BoxStream<pb::ExportItem>;

    async fn export(&self, _: Request<pb::ExportRequest>) -> Reply<Self::ExportStream> {
        let items: Vec<Result<pb::ExportItem, RpcStatus>> = self.with(|s| {
            use pb::export_item::Item;
            s.hosts
                .iter()
                .map(|h| Item::Host(h.clone()))
                .chain(
                    s.baseline
                        .entries
                        .iter()
                        .map(|e| Item::BaselineEntry(e.clone())),
                )
                .map(|item| Ok(pb::ExportItem { item: Some(item) }))
                .collect()
        });
        Ok(Response::new(Box::pin(tokio_stream::iter(items))))
    }

    async fn verify_audit(&self, _: Request<pb::VerifyAuditRequest>) -> Reply<pb::AuditReport> {
        Ok(Response::new(pb::AuditReport::default()))
    }

    async fn list_modules(&self, _: Request<pb::ListModulesRequest>) -> Reply<pb::ModuleList> {
        Ok(Response::new(pb::ModuleList {
            items: self.with(|s| s.status.modules.clone()),
        }))
    }

    async fn get_module(&self, r: Request<pb::GetModuleRequest>) -> Reply<pb::Module> {
        let id = r.into_inner().id;
        self.with(|s| s.status.modules.iter().find(|m| m.id == id).cloned())
            .map(Response::new)
            .ok_or_else(|| {
                RpcStatus::not_found(format!("module {id} is not built into this scribed"))
            })
    }

    async fn ack_alert(&self, r: Request<pb::AckAlertRequest>) -> Reply<pb::AckAlertReply> {
        let id = r.into_inner().id;
        self.with(|s| match s.alerts.iter_mut().find(|a| a.id == id) {
            Some(a) => {
                let changed = !a.acknowledged;
                a.acknowledged = true;
                Ok(Response::new(pb::AckAlertReply { changed }))
            }
            None => Err(RpcStatus::not_found(format!("no alert {id}"))),
        })
    }

    async fn set_mode(&self, r: Request<pb::SetModeRequest>) -> Reply<pb::SetModeReply> {
        let mode =
            scribe_api::mode_from_api(&r.into_inner().mode).map_err(RpcStatus::invalid_argument)?;
        Ok(Response::new(self.with(|s| {
            let previous = std::mem::replace(&mut s.status.mode, scribe_api::mode_to_api(mode));
            pb::SetModeReply {
                previous,
                mode: s.status.mode.clone(),
            }
        })))
    }

    async fn edit_baseline(
        &self,
        r: Request<pb::EditBaselineRequest>,
    ) -> Reply<pb::EditBaselineReply> {
        let r = r.into_inner();
        Ok(Response::new(self.with(|s| {
            let mut reply = pb::EditBaselineReply::default();
            for host in r.add {
                let host = host.to_ascii_lowercase();
                if s.baseline.entries.iter().any(|e| e.host == host) {
                    reply.unchanged.push(host);
                } else {
                    s.baseline.entries.push(pb::BaselineEntry {
                        host: host.clone(),
                        source: "manual".into(),
                        added_at_ms: now_ms(),
                    });
                    reply.added.push(host);
                }
            }
            for host in r.remove {
                let host = host.to_ascii_lowercase();
                let before = s.baseline.entries.len();
                s.baseline.entries.retain(|e| e.host != host);
                if s.baseline.entries.len() < before {
                    reply.removed.push(host);
                } else {
                    reply.unchanged.push(host);
                }
            }
            for h in &mut s.hosts {
                h.on_list = s.baseline.entries.iter().any(|e| e.host == h.name);
            }
            reply
        })))
    }

    async fn reset(&self, r: Request<pb::ResetRequest>) -> Reply<pb::ResetReply> {
        let r = r.into_inner();
        let all = !(r.counters || r.caches || r.config);
        Ok(Response::new(self.with(|s| {
            let mut done = Vec::new();
            if all || r.config {
                done.push("config".to_owned());
            }
            if all || r.counters {
                s.status.counters = Some(pb::Counters::default());
                s.status.counters_since_ms = now_ms();
                done.push("counters".into());
            }
            if all || r.caches {
                done.push("caches".into());
            }
            pb::ResetReply {
                done,
                status: Some(s.status.clone()),
                ..Default::default()
            }
        })))
    }

    async fn hibernate(&self, r: Request<pb::HibernateRequest>) -> Reply<pb::Status> {
        let for_s = r.into_inner().for_s.unwrap_or(4 * 3600);
        Ok(Response::new(self.with(|s| {
            let now = now_ms();
            s.status.run_state = "hibernating".into();
            s.status.hibernating_since_ms.get_or_insert(now);
            s.status.hibernating_until_ms = Some(now + for_s as i64 * 1000);
            s.status.hibernated_by = "mock".into();
            s.status.clone()
        })))
    }

    async fn wakeup(&self, _: Request<pb::WakeupRequest>) -> Reply<pb::Status> {
        Ok(Response::new(self.with(|s| {
            s.status.run_state = "running".into();
            s.status.hibernating_since_ms = None;
            s.status.hibernating_until_ms = None;
            s.status.hibernated_by.clear();
            s.status.critical.retain(|c| c.kind != "hibernating");
            s.status.clone()
        })))
    }
}

/// A scenario served on a socket (named pipe on Windows); stops when dropped.
pub struct MockApiServer {
    pub socket: PathBuf,
    state: Arc<Mutex<Scenario>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl MockApiServer {
    /// Serves `scenario` at `socket` on the current Tokio runtime.
    pub fn start(scenario: Scenario, socket: &Path) -> Result<Self, String> {
        let listener = scribe_api::transport::bind(socket, &[]).map_err(|e| e.to_string())?;
        let state = Arc::new(Mutex::new(scenario));
        let routes = tonic::service::Routes::new(scribe_api::service(MockApi {
            state: state.clone(),
        }));
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = scribe_api::transport::serve(listener, routes, async {
                let _ = stopped.await;
            })
            .await;
        });
        Ok(Self {
            socket: socket.to_owned(),
            state,
            stop: Some(stop),
            task: Some(task),
        })
    }

    /// The scenario as control calls left it.
    pub fn scenario(&self) -> Scenario {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.socket);
    }
}

impl Drop for MockApiServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
