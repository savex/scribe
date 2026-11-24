//! scribed's process lifecycle: arguments, config, logging, storage, then wait for a stop signal.
//!
//! Exit codes: 0 success, 1 runtime failure, 2 usage or configuration error.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::future::Future;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use clap::Parser;
use scribe_alerts::{Dispatcher, LogOutput, WebhookOutput};
use scribe_core::{Clock, Observation, Sensor, SystemClock, VERSION};
use scribe_enrich::Enricher;
use scribe_module_api::ConfigDoc;
use scribe_policy::{Policy, ThreatSet};
use scribe_storage_api::{AlertRecord, StorageError, StoredEvent};
use scribe_storage_manager::{
    BufferLimits, CacheLimits, Registry, RunOptions, SpoolOptions, Storage, StorageManager,
};
use tracing::{error, info, warn};

use crate::api::{Api, ApiServer, Layout, SensorInfo, Snapshot};
use crate::chain::Chain;
use crate::config::{self, Settings};
use crate::logging;
use crate::modules::{self, ModuleHost, Output, OutputQueue, QUEUE};
use crate::pipeline::{self, Pipeline, Status, Writes};
use crate::security;

pub const EXIT_FAILURE: u8 = 1;
pub const EXIT_CONFIG: u8 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "scribed",
    version = VERSION,
    about = "scribe daemon: tracks outgoing connections from this host"
)]
pub struct Args {
    /// Config file to use instead of SCRIBE_CONFIG or the OS default
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Check the config, print the effective config and exit
    #[arg(long)]
    pub check_config: bool,

    /// Run under the Windows service control manager (set by the installer; Windows only)
    #[arg(long)]
    pub service: bool,

    /// Store a secret (e.g. a webhook's `secret`) read from standard input under this reference
    /// (file:, keychain:, dpapi:, secret-service:) and exit
    #[arg(long, value_name = "REFERENCE", conflicts_with_all = ["check_config", "service"])]
    pub set_secret: Option<String>,

    /// With --set-secret: store a new random key and print it, instead of reading standard input
    #[arg(long, requires = "set_secret")]
    pub generate: bool,
}

/// Entry point of the `scribed` binary.
pub fn main() -> ExitCode {
    let args = Args::parse();
    if let Some(reference) = &args.set_secret {
        let value = if args.generate {
            None
        } else {
            let mut input = Vec::new();
            if let Err(e) = std::io::Read::read_to_end(&mut std::io::stdin(), &mut input) {
                eprintln!("scribed: cannot read the secret from standard input: {e}");
                return ExitCode::from(EXIT_FAILURE);
            }
            Some(input)
        };
        return match set_secret(reference, value) {
            Ok(message) => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("scribed: {e}");
                ExitCode::from(EXIT_CONFIG)
            }
        };
    }
    if args.service {
        #[cfg(windows)]
        return crate::service::run_windows_service();
        #[cfg(not(windows))]
        {
            eprintln!("scribed: --service is for Windows; use the systemd unit or launchd plist in packaging/");
            return ExitCode::from(EXIT_CONFIG);
        }
    }
    run(
        args,
        std::env::var_os("SCRIBE_CONFIG"),
        std::env::var("SCRIBE_LOG").ok(),
    )
}

/// `scribed --set-secret <reference>`: store `value` (one trailing newline dropped), or with
/// `None` a new random 32-byte key as hex, which the message then shows so it can be given to
/// the receiver. Returns what to print.
pub fn set_secret(reference: &str, value: Option<Vec<u8>>) -> Result<String, String> {
    let r: scribe_secrets::SecretRef = reference.parse().map_err(|e| format!("{e}"))?;
    match value {
        Some(mut bytes) => {
            if bytes.ends_with(b"\n") {
                bytes.pop();
                if bytes.ends_with(b"\r") {
                    bytes.pop();
                }
            }
            if bytes.is_empty() {
                return Err(
                    "nothing on standard input; pipe the secret in, or use --generate".into(),
                );
            }
            let stored = scribe_secrets::store(&r, &bytes);
            bytes.fill(0);
            stored.map_err(|e| e.to_string())?;
            Ok(format!("stored the secret in {r}"))
        }
        None => {
            let mut raw = [0u8; 32];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut raw)
                .map_err(|_| "no random bytes available".to_owned())?;
            let key: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            raw.fill(0);
            scribe_secrets::store(&r, key.as_bytes()).map_err(|e| e.to_string())?;
            Ok(format!(
                "stored a new key in {r}; the webhook receiver checks signatures with this key:\n{key}"
            ))
        }
    }
}

/// Runs scribed with explicit inputs, so tests don't depend on the process environment.
pub fn run(args: Args, config_env: Option<OsString>, log_filter: Option<String>) -> ExitCode {
    run_until(args, config_env, log_filter, shutdown_signal())
}

/// [`run`] that stops when `shutdown` completes (the Windows service stop request).
pub fn run_until(
    args: Args,
    config_env: Option<OsString>,
    log_filter: Option<String>,
    shutdown: impl Future<Output = ()>,
) -> ExitCode {
    let settings = match config::load_settings(args.config.as_deref(), config_env) {
        Ok(settings) => settings,
        Err(e) => {
            eprintln!("scribed: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    if args.check_config {
        print!("{}", settings.effective_toml());
        return ExitCode::SUCCESS;
    }

    let (guard, warnings) = match logging::init(&settings.log, log_filter.as_deref()) {
        Ok(logger) => logger,
        Err(e) => {
            eprintln!("scribed: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    for warning in warnings.iter().chain(&settings.warnings) {
        warn!("{warning}");
    }

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")
        .and_then(|rt| rt.block_on(serve(settings, shutdown)));
    let code = match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            eprintln!("scribed: {e:#}");
            ExitCode::from(EXIT_FAILURE)
        }
    };
    drop(guard);
    code
}

/// Opens storage, starts the platform sensor and runs the capture pipeline until `shutdown`
/// completes.
pub async fn serve(settings: Settings, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
    let sensor = platform_sensor(&settings);
    let options = ServeOptions {
        commands: None,
        api_socket: Some(settings.api_socket.clone()),
    };
    serve_full(settings, sensor, options, shutdown).await
}

/// What [`serve_full`] runs besides capture.
#[derive(Debug, Default)]
pub struct ServeOptions {
    /// Commands from the caller (tests); the local API sends its own.
    pub commands: Option<tokio::sync::mpsc::Receiver<Command>>,
    /// Serve the local API here. [`serve`] uses `[api] socket`; tests pass a temp path or none.
    pub api_socket: Option<PathBuf>,
}

/// Observations waiting between the sensor thread and the pipeline.
pub const OBSERVATION_QUEUE: usize = 4096;
/// Entries in the DNS (IP → name) cache.
pub const DNS_CACHE_ENTRIES: usize = 100_000;

/// Requests to the running daemon (`scribe daemon …`; the local API sends them from phase 10).
/// Each one answers with the status after it ran.
#[derive(Debug)]
pub enum Command {
    Hibernate {
        for_: Option<Duration>,
        caller: String,
        reply: tokio::sync::oneshot::Sender<Status>,
    },
    Wakeup {
        caller: String,
        reply: tokio::sync::oneshot::Sender<Status>,
    },
    /// `reset --counters` / `--caches` (`--config` is a reload, see SIGHUP).
    Reset {
        counters: bool,
        caches: bool,
        caller: String,
        reply: tokio::sync::oneshot::Sender<Status>,
    },
    /// `scribe mode`: answers with the previous mode.
    SetMode {
        mode: scribe_core::Mode,
        caller: String,
        reply: tokio::sync::oneshot::Sender<scribe_core::Mode>,
    },
    /// `scribe baseline add|rm`.
    EditBaseline {
        add: Vec<String>,
        remove: Vec<String>,
        caller: String,
        reply: tokio::sync::oneshot::Sender<pipeline::BaselineEdit>,
    },
    /// `scribe alerts ack`: answers whether it was new.
    Acknowledge {
        id: u64,
        alert: scribe_core::Alert,
        state: Option<scribe_storage_api::AlertState>,
        caller: String,
        reply: tokio::sync::oneshot::Sender<bool>,
    },
    /// Store an `audit` event (refused API calls), sealed into the chain like the others.
    Audit { message: String },
    Status {
        reply: tokio::sync::oneshot::Sender<Status>,
    },
    /// `reset --config` (also SIGHUP): re-read the config file and apply what can change live.
    Reload {
        caller: String,
        reply: tokio::sync::oneshot::Sender<Result<ReloadReport, String>>,
    },
    /// Everything the API reports from the loop: status, sensor, config and rates.
    Describe {
        reply: tokio::sync::oneshot::Sender<Box<Snapshot>>,
    },
}

/// What a config reload did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadReport {
    /// Changed keys that now apply.
    pub applied: Vec<String>,
    /// Changed keys that apply after a restart.
    pub needs_restart: Vec<String>,
}

#[cfg(unix)]
type Hangup = Option<tokio::signal::unix::Signal>;
#[cfg(not(unix))]
type Hangup = ();

#[cfg(unix)]
fn hangup_signal() -> Hangup {
    use tokio::signal::unix::{signal, SignalKind};
    signal(SignalKind::hangup()).ok()
}

#[cfg(not(unix))]
fn hangup_signal() -> Hangup {}

/// Completes on SIGHUP (Unix only).
#[cfg(unix)]
async fn hangup(signal: &mut Hangup) {
    match signal {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending().await,
    }
}

#[cfg(not(unix))]
async fn hangup(_signal: &mut Hangup) {
    std::future::pending::<()>().await
}

/// Re-read the config `running` came from and apply what can change live (specs 8.5.2).
/// Everything that can fail is checked before anything changes.
async fn reload(
    running: &mut Settings,
    pipeline: &mut Pipeline,
    storage: &Storage,
    clock: &Arc<dyn Clock>,
    caller: &str,
) -> Result<(ReloadReport, Writes, Option<Dispatcher>), String> {
    let new = config::reload::reread(running).map_err(|e| e.to_string())?;
    let plan = config::reload::plan(running, new);
    // Built first: a webhook whose secret can't be read rejects the whole reload.
    let outputs = if plan.changed("alerts") {
        Some(alert_outputs(&plan.settings, clock.clone())?)
    } else {
        None
    };
    let threats = if plan.changed("policy") {
        Some(load_threats(&plan.settings).map_err(|e| format!("{e:#}"))?)
    } else {
        None
    };
    let baseline = if plan.changed("profile") {
        match storage.state().baseline(&plan.settings.profile).await {
            Ok(b) => Some(b.entries.into_iter().map(|e| e.host).collect::<Vec<_>>()),
            Err(StorageError::NotImplemented(_)) => Some(Vec::new()),
            Err(e) => {
                return Err(format!(
                    "cannot read the baseline of profile \"{}\": {e}",
                    plan.settings.profile
                ))
            }
        }
    } else {
        None
    };
    let mut needs_restart: Vec<String> =
        plan.needs_restart.iter().map(|k| (*k).to_owned()).collect();
    if plan.changed("modules") {
        let keys = pipeline
            .modules_mut()
            .reconfigure(&ConfigDoc::new(&plan.settings.text))?;
        needs_restart.extend(keys);
    }
    let settings = &plan.settings;
    if let Some(threats) = threats {
        let policy = pipeline.policy_mut();
        policy.set_config(settings.policy_config());
        policy.set_threats(threats);
    }
    if plan.changed("mode") {
        pipeline.policy_mut().set_mode(settings.mode);
    }
    if let Some(hosts) = baseline {
        pipeline.set_profile(settings.profile.clone());
        pipeline.policy_mut().replace_baseline(hosts);
    }
    if plan.changed("daemon") {
        pipeline.set_max_hibernate(settings.config.daemon.max_hibernate.map(|d| d.get()));
    }
    if plan.changed("log.level") {
        if let Err(e) = logging::set_level(settings.log.level.as_str()) {
            warn!("cannot change the log level: {e}");
        }
    }
    for warning in &settings.warnings {
        warn!("{warning}");
    }
    let report = ReloadReport {
        applied: plan.applied.iter().map(|k| (*k).to_owned()).collect(),
        needs_restart,
    };
    let message = format!(
        "config reloaded by {caller}: applied [{}]; needs restart [{}]",
        report.applied.join(", "),
        report.needs_restart.join(", ")
    );
    info!("{message}");
    let mut writes = Writes::default();
    writes.events.push(audit(clock.now(), message));
    *running = plan.settings;
    Ok((report, writes, outputs))
}

/// [`serve`] with a given sensor (tests pass `FakeSensor`). Observations still queued at shutdown
/// are processed before storage closes.
pub async fn serve_with(
    settings: Settings,
    sensor: Box<dyn Sensor>,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    serve_controlled(settings, sensor, None, shutdown).await
}

async fn next_command(rx: &mut Option<tokio::sync::mpsc::Receiver<Command>>) -> Option<Command> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// [`serve_with`] that also takes [`Command`]s.
pub async fn serve_controlled(
    settings: Settings,
    sensor: Box<dyn Sensor>,
    commands: Option<tokio::sync::mpsc::Receiver<Command>>,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    let options = ServeOptions {
        commands,
        api_socket: None,
    };
    serve_full(settings, sensor, options, shutdown).await
}

/// The next command from the caller or from the local API.
async fn next_of(
    a: &mut Option<tokio::sync::mpsc::Receiver<Command>>,
    b: &mut Option<tokio::sync::mpsc::Receiver<Command>>,
) -> Option<Command> {
    tokio::select! {
        Some(cmd) = next_command(a) => Some(cmd),
        Some(cmd) = next_command(b) => Some(cmd),
        else => None,
    }
}

/// Commands waiting from the local API.
const API_COMMANDS: usize = 64;

/// Opens the API socket (named pipe on Windows) and lets `groups` in; on failure scribed keeps
/// capturing without it (and says why).
fn bind_api(path: &std::path::Path, groups: &[&str]) -> Option<scribe_api::transport::Listener> {
    match scribe_api::transport::bind(path, groups) {
        Ok(listener) => {
            info!(socket = %path.display(), "local API listening");
            Some(listener)
        }
        Err(e) => {
            warn!("local API not available ({e}); scribe and the UI cannot reach this scribed");
            None
        }
    }
}

/// Flows and stored events per second over the last minute (`scribe daemon status`).
#[derive(Default)]
struct Rates {
    samples: VecDeque<(SystemTime, u64, u64)>,
}

const RATE_WINDOW: Duration = Duration::from_secs(60);

impl Rates {
    fn sample(&mut self, now: SystemTime, flows: u64, events: u64) {
        self.samples.push_back((now, flows, events));
        while let Some((t, ..)) = self.samples.front() {
            match now.duration_since(*t) {
                Ok(age) if age > RATE_WINDOW => {
                    self.samples.pop_front();
                }
                _ => break,
            }
        }
    }

    fn per_second(&self) -> (f64, f64) {
        let (Some(first), Some(last)) = (self.samples.front(), self.samples.back()) else {
            return (0.0, 0.0);
        };
        let secs = last
            .0
            .duration_since(first.0)
            .unwrap_or_default()
            .as_secs_f64();
        if secs <= 0.0 {
            return (0.0, 0.0);
        }
        (
            last.1.saturating_sub(first.1) as f64 / secs,
            last.2.saturating_sub(first.2) as f64 / secs,
        )
    }
}

/// Events queued for storage so far (the busiest sink's count).
fn events_queued(storage: &Storage) -> u64 {
    storage
        .sink_status()
        .iter()
        .map(|s| s.queued)
        .max()
        .unwrap_or(0)
}

/// Running without process info on a system that has a native sensor.
fn is_fallback(sensor: &dyn Sensor) -> bool {
    cfg!(any(target_os = "linux", windows)) && !sensor.has_process_info()
}

/// [`serve`] with every part chosen by the caller.
pub async fn serve_full(
    settings: Settings,
    mut sensor: Box<dyn Sensor>,
    options: ServeOptions,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    let ServeOptions {
        mut commands,
        api_socket,
    } = options;
    info!(version = VERSION, "scribed starting");
    for line in settings.summary() {
        info!("{line}");
    }

    for dir in [&settings.data_dir, &settings.limits.spool_dir] {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create folder {}", dir.display()))?;
    }
    security::strict_modes(&settings).map_err(|e| anyhow::anyhow!("refusing to start: {e}"))?;
    let chain = Chain::open(&settings.data_dir).map_err(anyhow::Error::msg)?;
    let marker = settings.data_dir.join(RUNNING_MARKER);
    let unclean = std::fs::read_to_string(&marker).ok();

    let registry = Registry::with_builtin();
    let manager =
        StorageManager::from_config(&registry, &settings.storage).context("cannot open storage")?;
    match manager.migrate().await {
        Ok(()) => info!("storage ready"),
        Err(StorageError::NotImplemented(op)) => {
            warn!("storage backend is not implemented yet ({op}); nothing will be stored")
        }
        Err(e) => return Err(e).context("storage migration failed"),
    }

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let started_at = clock.now();
    let limits = &settings.limits;
    let storage = Arc::new(manager.start(RunOptions {
        clock: clock.clone(),
        spool: Some(SpoolOptions::new(
            &limits.spool_dir,
            limits.spool_max_size,
            limits.spool_min_free,
        )),
        buffer: BufferLimits {
            max_events: limits.buffer_events,
            max_memory: limits.buffer_memory,
        },
        cache: CacheLimits {
            max_hosts: limits.cache_hosts,
            max_memory: limits.cache_memory,
        },
        ..RunOptions::default()
    }));

    let mut host = ModuleHost::new(
        modules::instantiate(
            &modules::builtin(),
            settings.config.modules.enabled.get_ref(),
        ),
        &ConfigDoc::new(&settings.text),
    )
    .map_err(anyhow::Error::msg)?
    .with_data_dir(settings.data_dir.clone());
    let mut state = BTreeMap::new();
    for id in host.ids() {
        match storage.state().module_state(id).await {
            Ok(s) => {
                state.insert(id.to_owned(), s);
            }
            Err(StorageError::NotImplemented(_)) => {}
            Err(e) => warn!(module = id, "cannot read module state: {e}"),
        }
    }
    let queue = OutputQueue::new(QUEUE);
    for (id, started) in host.start(clock.clone(), |id| queue.emitter(id), state) {
        match started {
            Ok(()) => info!(module = id, "module {id} started"),
            Err(e) => warn!(module = id, "module {id} did not start: {e}"),
        }
    }

    let threats = load_threats(&settings)?;
    let baseline = match storage.state().baseline(&settings.profile).await {
        Ok(b) => b.entries.into_iter().map(|e| e.host).collect(),
        Err(StorageError::NotImplemented(_)) => Vec::new(),
        Err(e) => {
            warn!(
                "cannot read the baseline of profile \"{}\": {e}",
                settings.profile
            );
            Vec::new()
        }
    };
    let known_processes = match storage.state().process_hosts(None).await {
        Ok(rows) => rows.into_iter().map(|r| r.process).collect(),
        Err(StorageError::NotImplemented(_)) => Vec::new(),
        Err(e) => {
            warn!("cannot read known processes: {e}");
            Vec::new()
        }
    };
    let listed = baseline.len();
    let mut policy = Policy::new(settings.policy_config(), clock.clone())
        .with_baseline(baseline)
        .with_known_processes::<Vec<String>, String>(known_processes)
        .with_threats(threats);
    restore_alerts(&mut policy, storage.state(), clock.now()).await;
    info!(
        mode = %policy.mode(),
        profile = %settings.profile,
        baseline = listed,
        "policy ready"
    );
    let enricher = Enricher::new(clock.clone(), DNS_CACHE_ENTRIES);
    let mut pipeline = Pipeline::new(
        clock.clone(),
        settings.profile.clone(),
        enricher,
        host,
        policy,
    )
    .with_max_hibernate(settings.config.daemon.max_hibernate.map(|d| d.get()));

    // The sensor pushes into a std channel from its own threads; a forwarding thread hands
    // observations to the async loop through a bounded queue.
    let (sensor_tx, sensor_rx) = std::sync::mpsc::channel::<Observation>();
    let (obs_tx, mut obs_rx) = tokio::sync::mpsc::channel::<Observation>(OBSERVATION_QUEUE);
    std::thread::Builder::new()
        .name("scribe-sensor-forward".into())
        .spawn(move || {
            for obs in sensor_rx {
                if obs_tx.blocking_send(obs).is_err() {
                    break;
                }
            }
        })
        .context("cannot start the sensor thread")?;
    let restart_tx = sensor_tx.clone();
    sensor.set_payload(pipeline.modules().needs_payload());
    let mut capturing = match sensor.start(sensor_tx) {
        Ok(()) => {
            info!(
                sensor = sensor.name(),
                process_info = sensor.has_process_info(),
                "capture started"
            );
            true
        }
        Err(e) => {
            warn!(
                sensor = sensor.name(),
                "capture is not available ({e}); scribed runs without a sensor"
            );
            false
        }
    };

    let (alerts_tx, _) = tokio::sync::broadcast::channel::<AlertRecord>(crate::api::ALERT_BACKLOG);
    let outputs = alert_outputs(&settings, clock.clone()).map_err(|e| anyhow::anyhow!(e))?;
    let mut writer = Writer::new(chain, alerts_tx.clone(), outputs);
    let mut started = Writes::default();
    if let Some(previous) = unclean {
        warn!(
            "the previous run did not stop cleanly ({})",
            previous.trim()
        );
        started.events.push(audit(
            clock.now(),
            format!(
                "previous run did not stop cleanly (crash or kill): {}",
                previous.trim()
            ),
        ));
    }
    std::fs::write(
        &marker,
        format!(
            "pid {} started {}\n",
            std::process::id(),
            pipeline::humantime_rfc3339(clock.now())
        ),
    )
    .with_context(|| format!("cannot write {}", marker.display()))?;
    started.events.push(audit(
        clock.now(),
        format!("scribed {VERSION} started (sensor {})", sensor.name()),
    ));
    writer.apply(&storage, pipeline.profile(), started).await;

    // The socket is opened before dropping privileges: its folder belongs to root.
    let (stop_api, stopping_api) = tokio::sync::watch::channel(false);
    let mut api_commands = None;
    let admin_group = settings.config.api.admin_group.get_ref().clone();
    let groups = [scribe_api::transport::READ_GROUP, admin_group.as_str()];
    let api_server = match api_socket.as_deref().and_then(|p| bind_api(p, &groups)) {
        Some(listener) => {
            let (tx, rx) = tokio::sync::mpsc::channel(API_COMMANDS);
            api_commands = Some(rx);
            let api = Api {
                commands: tx,
                storage: storage.clone(),
                alerts: alerts_tx.clone(),
                stopping: stopping_api,
                policy: scribe_api::access::AccessPolicy {
                    admin_group: admin_group.clone(),
                },
                layout: Layout::of(&settings),
                audit_key: writer.chain.key().clone(),
            };
            let enabled = settings.config.modules.enabled.get_ref();
            #[allow(unused_mut)]
            let mut modules = tonic::service::Routes::default();
            #[cfg(feature = "url")]
            if enabled.iter().any(|id| id == scribe_module_url::ID) {
                let reader = Arc::new(crate::api::StoredRecords(storage.clone()));
                modules = modules.add_service(scribe_module_url::api::service(reader));
            }
            let _ = enabled;
            Some(ApiServer::spawn(listener, api, stop_api, modules))
        }
        None => {
            drop((stop_api, stopping_api));
            None
        }
    };
    let modules_built: Vec<(&'static str, u32)> = modules::builtin()
        .iter()
        .map(|m| (m.id, (m.make)().manifest().version))
        .collect();
    let mut config_loaded = clock.now();
    let mut rates = Rates::default();
    let hours_keep = settings.config.storage.hours.keep.map(Duration::from);
    let mut next_prune = clock.now();

    let user = settings.config.daemon.user.trim();
    if !user.is_empty() {
        crate::privileges::drop_to(user, &settings.data_dir)
            .map_err(|e| anyhow::anyhow!("cannot run as {user}: {e}"))?;
        info!(user, "running as {user}");
    }
    crate::service::notify("READY=1\nSTATUS=capturing");
    info!("scribed started; waiting for a stop signal");
    let mut running = settings.clone();
    let mut hup = hangup_signal();
    let mut drain = Drain::default();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            Some(obs) = obs_rx.recv() => {
                let writes = pipeline.process(obs);
                writer.apply(&storage, pipeline.profile(), writes).await;
            }
            Some(cmd) = next_of(&mut commands, &mut api_commands) => {
                let was = pipeline.is_hibernating();
                let reply = match cmd {
                    Command::Describe { reply } => {
                        let (flows_per_s, events_per_s) = rates.per_second();
                        let snapshot = Snapshot {
                            status: pipeline.status(),
                            sensor: SensorInfo {
                                name: sensor.name().to_owned(),
                                process_info: sensor.has_process_info(),
                                capturing,
                                fallback: is_fallback(sensor.as_ref()),
                            },
                            started: started_at,
                            now: clock.now(),
                            config_path: running.source.to_string(),
                            config_loaded,
                            flows_per_s,
                            events_per_s,
                            module_drops: pipeline
                                .modules()
                                .ids()
                                .into_iter()
                                .map(|id| (id.to_owned(), queue.dropped_by(id)))
                                .collect(),
                            modules_built: modules_built.clone(),
                            sealed_seq: writer.chain.seq(),
                        };
                        let _ = reply.send(Box::new(snapshot));
                        continue;
                    }
                    Command::Hibernate { for_, caller, reply } => {
                        let writes = pipeline.hibernate(for_, &caller);
                        writer.apply(&storage, pipeline.profile(), writes).await;
                        storage.flush().await;
                        reply
                    }
                    Command::Wakeup { caller, reply } => {
                        let writes = pipeline.wakeup(&caller);
                        writer.apply(&storage, pipeline.profile(), writes).await;
                        reply
                    }
                    Command::Reset { counters, caches, caller, reply } => {
                        if counters {
                            pipeline.reset_counters();
                        }
                        if caches {
                            storage.flush().await;
                            storage.clear_cache();
                            pipeline.clear_caches();
                        }
                        let parts: Vec<&str> = [(counters, "counters"), (caches, "caches")]
                            .into_iter()
                            .filter_map(|(on, name)| on.then_some(name))
                            .collect();
                        info!(counters, caches, caller = %caller, "runtime reset");
                        let mut writes = Writes::default();
                        writes.events.push(audit(
                            clock.now(),
                            format!("runtime reset by {caller}: {}", parts.join(", ")),
                        ));
                        writer.apply(&storage, pipeline.profile(), writes).await;
                        reply
                    }
                    Command::SetMode { mode, caller, reply } => {
                        let (previous, writes) = pipeline.set_mode(mode, &caller);
                        info!(caller = %caller, "mode set to {mode} (was {previous})");
                        writer.apply(&storage, pipeline.profile(), writes).await;
                        let _ = reply.send(previous);
                        continue;
                    }
                    Command::EditBaseline { add, remove, caller, reply } => {
                        let (edit, writes) = pipeline.edit_baseline(&add, &remove, &caller);
                        info!(
                            caller = %caller,
                            added = edit.added.len(),
                            removed = edit.removed.len(),
                            "baseline edited"
                        );
                        writer.apply(&storage, pipeline.profile(), writes).await;
                        let _ = reply.send(edit);
                        continue;
                    }
                    Command::Acknowledge { id, alert, state, caller, reply } => {
                        let (changed, writes) = pipeline.acknowledge(id, &alert, state, &caller);
                        info!(caller = %caller, alert = id, changed, "alert acknowledged");
                        writer.apply(&storage, pipeline.profile(), writes).await;
                        let _ = reply.send(changed);
                        continue;
                    }
                    Command::Audit { message } => {
                        let mut writes = Writes::default();
                        writes.events.push(audit(clock.now(), message));
                        writer.apply(&storage, pipeline.profile(), writes).await;
                        continue;
                    }
                    Command::Status { reply } => reply,
                    Command::Reload { caller, reply } => {
                        let result = reload(&mut running, &mut pipeline, &storage, &clock, &caller).await;
                        let result = match result {
                            Ok((report, writes, outputs)) => {
                                if let Some(outputs) = outputs {
                                    writer.set_outputs(outputs);
                                }
                                writer.apply(&storage, pipeline.profile(), writes).await;
                                config_loaded = clock.now();
                                Ok(report)
                            }
                            Err(e) => {
                                warn!("config reload by {caller} rejected; the running config stays: {e}");
                                Err(e)
                            }
                        };
                        let _ = reply.send(result);
                        continue;
                    }
                };
                follow_state(was, &pipeline, sensor.as_mut(), &restart_tx, &mut capturing);
                let _ = reply.send(pipeline.status());
            }
            _ = hangup(&mut hup) => {
                match reload(&mut running, &mut pipeline, &storage, &clock, "SIGHUP").await {
                    Ok((_, writes, outputs)) => {
                        if let Some(outputs) = outputs {
                            writer.set_outputs(outputs);
                        }
                        writer.apply(&storage, pipeline.profile(), writes).await;
                        config_loaded = clock.now();
                    }
                    Err(e) => warn!("config reload (SIGHUP) rejected; the running config stays: {e}"),
                }
            }
            _ = ticker.tick() => {
                let was = pipeline.is_hibernating();
                let writes = pipeline.tick();
                writer.apply(&storage, pipeline.profile(), writes).await;
                writer.outputs.tick();
                follow_state(was, &pipeline, sensor.as_mut(), &restart_tx, &mut capturing);
                pipeline.modules_mut().tick();
                drain.run(queue.take(), &storage).await;
                rates.sample(clock.now(), pipeline.counters().flows, events_queued(&storage));
                if let Some(keep) = hours_keep {
                    let now = clock.now();
                    if now >= next_prune {
                        next_prune = now + PRUNE_EVERY;
                        prune_hours(storage.state(), now, keep).await;
                    }
                }
            }
        }
    }
    info!("stop signal received; shutting down");
    crate::service::notify("STOPPING=1");
    if let Some(server) = api_server {
        server.shutdown().await;
        // Only the daemon that bound the socket removes it (a pipe goes away by itself).
        #[cfg(unix)]
        if let Some(path) = api_socket.as_deref() {
            let _ = std::fs::remove_file(path);
        }
    }
    drop(api_commands);

    sensor.stop();
    drop(sensor);
    drop(restart_tx);
    // Whatever the sensor delivered before it stopped is still processed.
    while let Ok(Some(obs)) = tokio::time::timeout(Duration::from_millis(200), obs_rx.recv()).await
    {
        let writes = pipeline.process(obs);
        writer.apply(&storage, pipeline.profile(), writes).await;
    }
    let mut writes = pipeline.flush();
    writes
        .events
        .push(audit(clock.now(), "scribed stopped".into()));
    writer.apply(&storage, pipeline.profile(), writes).await;
    let counters = pipeline.counters().clone();
    info!(
        observations = counters.observations,
        flows = counters.flows,
        alerts = counters.alerts,
        "pipeline stopped"
    );

    let host = pipeline.modules_mut();
    host.stop();
    drain.run(queue.take(), &storage).await;
    for status in host.status() {
        info!(module = status.id, "module {} stopped", status.id);
    }
    if queue.dropped() > 0 {
        warn!(
            dropped = queue.dropped(),
            "module output dropped because its queue was full"
        );
    }

    let late = writer.outputs.close(OUTPUTS_GRACE);
    if !late.is_empty() {
        warn!("alert outputs still busy at shutdown: {}", late.join(", "));
    }
    match Arc::try_unwrap(storage) {
        Ok(storage) => storage.shutdown().await,
        Err(storage) => {
            warn!("storage is still in use at shutdown; flushing it instead");
            storage.flush().await;
        }
    }
    let _ = std::fs::remove_file(&marker);
    info!("scribed stopped");
    Ok(())
}

/// Writes queued module output to storage; warns once per kind of failure.
#[derive(Default)]
struct Drain {
    warned: bool,
}

impl Drain {
    async fn run(&mut self, items: Vec<Output>, storage: &Storage) {
        let mut events: Vec<StoredEvent> = Vec::new();
        for item in items {
            match item {
                Output::Event(e) => events.push(e),
                Output::State { module, key, value } => {
                    if let Err(e) = storage.state().put_module_state(module, &key, &value).await {
                        self.warn(&e);
                    }
                }
            }
        }
        if !events.is_empty() {
            storage.publish(&events);
        }
    }

    fn warn(&mut self, e: &StorageError) {
        if !self.warned {
            self.warned = true;
            warn!("module output not stored: {e}");
        }
    }
}

/// Completes on Ctrl-C, or on SIGTERM on Unix.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(e) => {
                warn!("cannot listen for SIGTERM ({e}); only Ctrl-C stops scribed");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// The sensor for this system, with the pcap sensor as the fallback when the native one can't
/// start (specs 8.4). macOS uses pcap until the Network Extension arrives (phase 9).
fn platform_sensor(settings: &Settings) -> Box<dyn Sensor> {
    let iface = settings.config.sensor.interface.trim();
    let pcap = scribe_sensor_pcap::PcapSensor::new((!iface.is_empty()).then(|| iface.to_owned()));
    #[cfg(target_os = "linux")]
    return Box::new(FallbackSensor::new(
        Box::new(scribe_sensor_linux::EbpfSensor),
        Box::new(pcap),
    ));
    #[cfg(windows)]
    return Box::new(FallbackSensor::new(
        Box::new(scribe_sensor_windows::EtwSensor),
        Box::new(pcap),
    ));
    #[cfg(not(any(target_os = "linux", windows)))]
    return Box::new(pcap);
}

/// A native sensor with a fallback: `start` tries the native one and, if it can't run, the
/// fallback; status then reports the fallback (no process info).
pub struct FallbackSensor {
    primary: Box<dyn Sensor>,
    fallback: Box<dyn Sensor>,
    using_fallback: bool,
}

impl FallbackSensor {
    pub fn new(primary: Box<dyn Sensor>, fallback: Box<dyn Sensor>) -> Self {
        Self {
            primary,
            fallback,
            using_fallback: false,
        }
    }

    fn active(&self) -> &dyn Sensor {
        if self.using_fallback {
            self.fallback.as_ref()
        } else {
            self.primary.as_ref()
        }
    }
}

impl Sensor for FallbackSensor {
    fn name(&self) -> &'static str {
        self.active().name()
    }

    fn has_process_info(&self) -> bool {
        self.active().has_process_info()
    }

    fn set_payload(&mut self, needed: bool) {
        self.primary.set_payload(needed);
        self.fallback.set_payload(needed);
    }

    fn start(
        &mut self,
        out: std::sync::mpsc::Sender<Observation>,
    ) -> Result<(), scribe_core::SensorError> {
        if !self.using_fallback {
            match self.primary.start(out.clone()) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(
                        "{} sensor is not available ({e}); falling back to {} (no process info)",
                        self.primary.name(),
                        self.fallback.name()
                    );
                    self.using_fallback = true;
                }
            }
        }
        self.fallback.start(out)
    }

    fn stop(&mut self) {
        if self.using_fallback {
            self.fallback.stop();
        } else {
            self.primary.stop();
        }
    }
}

/// Read the threat lists that are files (relative paths are under `data_dir`). A list that can't
/// be read stops scribed: running without it would silently weaken caution mode. Lists with a
/// `url` are downloaded from plan phase 11 on and are skipped with a warning until then.
pub fn load_threats(settings: &Settings) -> anyhow::Result<ThreatSet> {
    let (files, skipped) = settings.threat_files();
    let mut set = ThreatSet::default();
    for (name, path, format) in files {
        let text = std::fs::read_to_string(&path).with_context(|| {
            format!("cannot read threat list \"{name}\" from {}", path.display())
        })?;
        let report = set.load(format, &text);
        info!(
            list = %name,
            entries = report.added,
            skipped_lines = report.skipped,
            "threat list loaded"
        );
    }
    for name in skipped {
        warn!(list = %name, "threat list downloads arrive in plan phase 11; list \"{name}\" is not used yet");
    }
    Ok(set)
}

/// How often old hourly buckets are deleted.
const PRUNE_EVERY: Duration = Duration::from_secs(3600);

/// Delete hourly buckets older than `keep` (`[storage.hours] keep`).
async fn prune_hours(state: &dyn scribe_storage_api::StateStore, now: SystemTime, keep: Duration) {
    let Some(cutoff) = now.checked_sub(keep) else {
        return;
    };
    match state.prune_host_hours(cutoff).await {
        Ok(0) | Err(StorageError::NotImplemented(_)) => {}
        Ok(n) => info!(removed = n, "old hourly counters deleted"),
        Err(e) => warn!("cannot delete old hourly counters: {e}"),
    }
}

/// Bring back acknowledgements, and dedupe for alerts still inside their window, from the state
/// store (specs 8.5), so a restart doesn't repeat alerts someone already handled.
async fn restore_alerts(
    policy: &mut Policy,
    state: &dyn scribe_storage_api::StateStore,
    now: SystemTime,
) {
    let states = match state.alert_states().await {
        Ok(states) => states,
        Err(StorageError::NotImplemented(_)) => return,
        Err(e) => {
            warn!("cannot read the stored alert state ({e}); acknowledged alerts may repeat");
            return;
        }
    };
    let window = policy.config().dedupe_window;
    let (mut acknowledged, mut recent) = (0usize, 0usize);
    for s in states {
        let fresh = now
            .duration_since(s.last_alerted)
            .map_or(true, |age| age < window);
        if s.acknowledged || fresh {
            policy.restore_alert(
                scribe_policy::alert_from_key(&s.key, s.last_alerted),
                s.acknowledged,
            );
            if s.acknowledged {
                acknowledged += 1;
            } else {
                recent += 1;
            }
        }
    }
    info!(acknowledged, recent, "alert state restored");
}

/// Marks a running daemon in `data_dir`; still there at the next start means a crash or kill.
pub const RUNNING_MARKER: &str = "scribed.running";

fn audit(ts: std::time::SystemTime, message: String) -> StoredEvent {
    StoredEvent::Audit(scribe_storage_api::AuditRecord {
        ts,
        message,
        link: None,
    })
}

/// How long alert outputs get at shutdown to finish their queues.
const OUTPUTS_GRACE: Duration = Duration::from_secs(3);

/// scribed's own alert outputs from `[alerts]` (phase 11). Fails when a webhook's secret can't
/// be read, so a start or reload with a broken webhook is refused rather than silently quiet.
pub fn alert_outputs(settings: &Settings, clock: Arc<dyn Clock>) -> Result<Dispatcher, String> {
    let config = &settings.config.alerts;
    let mut outputs: Vec<Arc<dyn scribe_core::AlertOutput>> = Vec::new();
    if config.log {
        outputs.push(Arc::new(LogOutput));
    }
    let machine = machine_name();
    for hook in &config.webhooks {
        let h = hook.get_ref();
        let reference: scribe_secrets::SecretRef = h
            .secret
            .parse()
            .map_err(|e| format!("webhook \"{}\": {e}", h.name))?;
        let secret = scribe_secrets::read(&reference)
            .map_err(|e| format!("webhook \"{}\": cannot read its secret: {e}", h.name))?;
        let client = scribe_net::Client::new(scribe_net::Options {
            timeout: h.timeout.get(),
            pin_sha256: h.pin_sha256.clone(),
            ..scribe_net::Options::default()
        })
        .map_err(|e| format!("webhook \"{}\": {e}", h.name))?;
        outputs.push(Arc::new(WebhookOutput::new(
            h.name.clone(),
            h.url.clone(),
            client,
            secret,
            machine.clone(),
            clock.clone(),
        )));
    }
    let dispatcher = Dispatcher::new(outputs, config.max_per_minute, clock);
    info!(
        outputs = %dispatcher.names().join(", "),
        max_per_minute = config.max_per_minute,
        "alert outputs ready"
    );
    Ok(dispatcher)
}

/// This machine's name for webhook payloads (`machine`).
pub fn machine_name() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: the buffer is valid for its length; gethostname writes at most that much.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        if rc == 0 {
            let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
            let name = String::from_utf8_lossy(&buf[..end]).into_owned();
            if !name.is_empty() {
                return name;
            }
        }
    }
    #[cfg(windows)]
    if let Some(name) = std::env::var_os("COMPUTERNAME") {
        return name.to_string_lossy().into_owned();
    }
    "unknown".to_owned()
}

/// Seals audit and alert records into the chain, applies pipeline writes to storage and hands
/// alerts to the outputs; storage errors are logged once until a write succeeds again.
struct Writer {
    chain: Chain,
    failing: bool,
    /// Sealed alerts for `WatchAlerts` clients.
    alerts: tokio::sync::broadcast::Sender<AlertRecord>,
    outputs: Dispatcher,
}

impl Writer {
    fn new(
        chain: Chain,
        alerts: tokio::sync::broadcast::Sender<AlertRecord>,
        outputs: Dispatcher,
    ) -> Self {
        Self {
            chain,
            failing: false,
            alerts,
            outputs,
        }
    }

    /// Swap the outputs after a reload; the old ones finish their queues on their own.
    fn set_outputs(&mut self, outputs: Dispatcher) {
        let old = std::mem::replace(&mut self.outputs, outputs);
        let _ = old.close(Duration::ZERO);
    }

    async fn apply(&mut self, storage: &Storage, profile: &str, mut writes: Writes) {
        if let Err(e) = self.chain.seal(&mut writes.events) {
            warn!("cannot save the audit chain state: {e}");
        }
        if self.alerts.receiver_count() > 0 {
            for event in &writes.events {
                if let StoredEvent::Alert(a) = event {
                    let _ = self.alerts.send(a.clone());
                }
            }
        }
        for alert in &writes.alerts {
            self.outputs.send(alert);
        }
        if writes.is_empty() {
            return;
        }
        let errors = pipeline::store(storage, profile, &writes).await;
        match errors.first() {
            Some(e) if !self.failing => {
                self.failing = true;
                warn!("pipeline writes not stored: {e}");
            }
            Some(_) => {}
            None => self.failing = false,
        }
    }
}

/// Stop the sensor when the pipeline started hibernating, start it again when it woke up.
fn follow_state(
    was_hibernating: bool,
    pipeline: &Pipeline,
    sensor: &mut dyn Sensor,
    tx: &std::sync::mpsc::Sender<Observation>,
    capturing: &mut bool,
) {
    match (was_hibernating, pipeline.is_hibernating()) {
        (false, true) => {
            sensor.stop();
            *capturing = false;
            if let pipeline::DaemonState::Hibernating { until, caller, .. } = pipeline.state() {
                warn!(
                    caller = %caller,
                    until = %until.map_or_else(|| "woken up".to_owned(), pipeline::humantime_rfc3339),
                    "hibernating: capture stopped"
                );
            }
        }
        (true, false) => match sensor.start(tx.clone()) {
            Ok(()) => {
                *capturing = true;
                info!(sensor = sensor.name(), "woke up: capture started again");
            }
            Err(e) => warn!(
                sensor = sensor.name(),
                "woke up, but capture is not available: {e}"
            ),
        },
        _ => {}
    }
}
