//! scribed's process lifecycle: arguments, config, logging, storage, then wait for a stop signal.
//!
//! Exit codes: 0 success, 1 runtime failure, 2 usage or configuration error.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::future::Future;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use scribe_core::{Clock, Observation, Sensor, SystemClock, VERSION};
use scribe_enrich::Enricher;
use scribe_module_api::ConfigDoc;
use scribe_policy::{Policy, ThreatSet};
use scribe_storage_api::{StorageError, StoredEvent};
use scribe_storage_manager::{
    BufferLimits, CacheLimits, Registry, RunOptions, SpoolOptions, Storage, StorageManager,
};
use tracing::{error, info, warn};

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
}

/// Entry point of the `scribed` binary.
pub fn main() -> ExitCode {
    run(
        Args::parse(),
        std::env::var_os("SCRIBE_CONFIG"),
        std::env::var("SCRIBE_LOG").ok(),
    )
}

/// Runs scribed with explicit inputs, so tests don't depend on the process environment.
pub fn run(args: Args, config_env: Option<OsString>, log_filter: Option<String>) -> ExitCode {
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
        .and_then(|rt| rt.block_on(serve(settings, shutdown_signal())));
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
    serve_with(settings, platform_sensor(), shutdown).await
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
        reply: tokio::sync::oneshot::Sender<Status>,
    },
    Status {
        reply: tokio::sync::oneshot::Sender<Status>,
    },
    /// `reset --config` (also SIGHUP): re-read the config file and apply what can change live.
    Reload {
        caller: String,
        reply: tokio::sync::oneshot::Sender<Result<ReloadReport, String>>,
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
    clock: &dyn Clock,
    caller: &str,
) -> Result<(ReloadReport, Writes), String> {
    let new = config::reload::reread(running).map_err(|e| e.to_string())?;
    let plan = config::reload::plan(running, new);
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
    Ok((report, writes))
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
    mut sensor: Box<dyn Sensor>,
    mut commands: Option<tokio::sync::mpsc::Receiver<Command>>,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
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
    let limits = &settings.limits;
    let storage = manager.start(RunOptions {
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
    });

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
    let policy = Policy::new(settings.policy_config(), clock.clone())
        .with_baseline(baseline)
        .with_known_processes::<Vec<String>, String>(known_processes)
        .with_threats(threats);
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
    match sensor.start(sensor_tx) {
        Ok(()) => info!(
            sensor = sensor.name(),
            process_info = sensor.has_process_info(),
            "capture started"
        ),
        Err(e) => warn!(
            sensor = sensor.name(),
            "capture is not available ({e}); scribed runs without a sensor"
        ),
    }

    let mut writer = Writer::new(chain);
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
            Some(cmd) = next_command(&mut commands) => {
                let was = pipeline.is_hibernating();
                let reply = match cmd {
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
                    Command::Reset { counters, caches, reply } => {
                        if counters {
                            pipeline.reset_counters();
                        }
                        if caches {
                            storage.flush().await;
                            storage.clear_cache();
                            pipeline.clear_caches();
                        }
                        info!(counters, caches, "runtime reset");
                        reply
                    }
                    Command::Status { reply } => reply,
                    Command::Reload { caller, reply } => {
                        let result = reload(&mut running, &mut pipeline, &storage, clock.as_ref(), &caller).await;
                        let result = match result {
                            Ok((report, writes)) => {
                                writer.apply(&storage, pipeline.profile(), writes).await;
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
                follow_state(was, &pipeline, sensor.as_mut(), &restart_tx);
                let _ = reply.send(pipeline.status());
            }
            _ = hangup(&mut hup) => {
                match reload(&mut running, &mut pipeline, &storage, clock.as_ref(), "SIGHUP").await {
                    Ok((_, writes)) => writer.apply(&storage, pipeline.profile(), writes).await,
                    Err(e) => warn!("config reload (SIGHUP) rejected; the running config stays: {e}"),
                }
            }
            _ = ticker.tick() => {
                let was = pipeline.is_hibernating();
                let writes = pipeline.tick();
                writer.apply(&storage, pipeline.profile(), writes).await;
                follow_state(was, &pipeline, sensor.as_mut(), &restart_tx);
                pipeline.modules_mut().tick();
                drain.run(&queue, &storage).await;
            }
        }
    }
    info!("stop signal received; shutting down");

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
    drain.run(&queue, &storage).await;
    for status in host.status() {
        info!(module = status.id, "module {} stopped", status.id);
    }
    if queue.dropped() > 0 {
        warn!(
            dropped = queue.dropped(),
            "module output dropped because its queue was full"
        );
    }

    storage.shutdown().await;
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
    async fn run(&mut self, queue: &OutputQueue, storage: &Storage) {
        let mut events: Vec<StoredEvent> = Vec::new();
        for item in queue.take() {
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

fn platform_sensor() -> Box<dyn Sensor> {
    #[cfg(target_os = "linux")]
    return Box::new(scribe_sensor_linux::EbpfSensor);
    #[cfg(windows)]
    return Box::new(scribe_sensor_windows::EtwSensor);
    // macOS: flows arrive from the Network Extension over XPC; pcap until that exists.
    #[cfg(not(any(target_os = "linux", windows)))]
    return Box::new(scribe_sensor_pcap::PcapSensor { interface: None });
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

/// Marks a running daemon in `data_dir`; still there at the next start means a crash or kill.
pub const RUNNING_MARKER: &str = "scribed.running";

fn audit(ts: std::time::SystemTime, message: String) -> StoredEvent {
    StoredEvent::Audit(scribe_storage_api::AuditRecord {
        ts,
        message,
        link: None,
    })
}

/// Seals audit and alert records into the chain, applies pipeline writes to storage and reports
/// alerts; storage errors are logged once until a write succeeds again.
struct Writer {
    chain: Chain,
    failing: bool,
}

impl Writer {
    fn new(chain: Chain) -> Self {
        Self {
            chain,
            failing: false,
        }
    }

    async fn apply(&mut self, storage: &Storage, profile: &str, mut writes: Writes) {
        if let Err(e) = self.chain.seal(&mut writes.events) {
            warn!("cannot save the audit chain state: {e}");
        }
        for alert in &writes.alerts {
            warn!(
                target: "scribe::alert",
                reason = %alert.reason,
                host = alert.host.as_deref().unwrap_or("-"),
                dst = %std::net::SocketAddr::new(alert.dst_ip, alert.dst_port),
                process = alert.process_path.as_deref().unwrap_or("-"),
                score = alert.score,
                "alert"
            );
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
) {
    match (was_hibernating, pipeline.is_hibernating()) {
        (false, true) => {
            sensor.stop();
            if let pipeline::DaemonState::Hibernating { until, caller, .. } = pipeline.state() {
                warn!(
                    caller = %caller,
                    until = %until.map_or_else(|| "woken up".to_owned(), pipeline::humantime_rfc3339),
                    "hibernating: capture stopped"
                );
            }
        }
        (true, false) => match sensor.start(tx.clone()) {
            Ok(()) => info!(sensor = sensor.name(), "woke up: capture started again"),
            Err(e) => warn!(
                sensor = sensor.name(),
                "woke up, but capture is not available: {e}"
            ),
        },
        _ => {}
    }
}
