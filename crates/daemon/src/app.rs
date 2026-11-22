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
use scribe_core::{Clock, Sensor, SystemClock, VERSION};
use scribe_module_api::ConfigDoc;
use scribe_storage_api::{StorageError, StoredEvent};
use scribe_storage_manager::{
    BufferLimits, Registry, RunOptions, SpoolOptions, Storage, StorageManager,
};
use tracing::{error, info, warn};

use crate::config::{self, Settings};
use crate::logging;
use crate::modules::{self, ModuleHost, Output, OutputQueue, QUEUE};

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

/// Opens storage, then runs until `shutdown` completes. The capture pipeline arrives in plan phase 5.
pub async fn serve(settings: Settings, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
    info!(version = VERSION, "scribed starting");
    for line in settings.summary() {
        info!("{line}");
    }

    for dir in [&settings.data_dir, &settings.limits.spool_dir] {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create folder {}", dir.display()))?;
    }

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
        ..RunOptions::default()
    });

    let sensor = platform_sensor();
    info!(
        sensor = sensor.name(),
        process_info = sensor.has_process_info(),
        "capture is not wired up yet (plan phase 5)"
    );

    let mut host = ModuleHost::new(
        modules::instantiate(
            &modules::builtin(),
            settings.config.modules.enabled.get_ref(),
        ),
        &ConfigDoc::new(&settings.text),
    )
    .map_err(anyhow::Error::msg)?;
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

    info!("scribed started; waiting for a stop signal");
    // Until the capture pipeline arrives (plan phase 5), only sources run; their output is
    // written once a second.
    let mut drain = Drain::default();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = ticker.tick() => {
                host.tick();
                drain.run(&queue, &storage).await;
            }
        }
    }
    info!("stop signal received; shutting down");

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
