//! scribed's process lifecycle: arguments, config, logging, storage, then wait for a stop signal.
//!
//! Exit codes: 0 success, 1 runtime failure, 2 usage or configuration error.

use std::ffi::OsString;
use std::future::Future;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context as _;
use clap::Parser;
use scribe_core::{Sensor, VERSION};
use scribe_storage_api::StorageError;
use scribe_storage_manager::{Registry, StorageManager};
use tracing::{error, info, warn};

use crate::config::{self, Settings};
use crate::logging;

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
    for warning in &warnings {
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
    let storage =
        StorageManager::from_config(&registry, &settings.storage).context("cannot open storage")?;
    match storage.migrate().await {
        Ok(()) => {}
        Err(StorageError::NotImplemented(op)) => {
            warn!("storage backend is not implemented yet ({op}); nothing will be stored")
        }
        Err(e) => return Err(e).context("storage migration failed"),
    }

    let sensor = platform_sensor();
    info!(
        sensor = sensor.name(),
        process_info = sensor.has_process_info(),
        "capture is not wired up yet (plan phase 5)"
    );

    info!("scribed started; waiting for a stop signal");
    shutdown.await;
    info!("stop signal received; shutting down");

    for sink in storage.sinks() {
        match sink.flush().await {
            Ok(()) | Err(StorageError::NotImplemented(_)) => {}
            Err(e) => warn!(sink = sink.name(), "flush failed: {e}"),
        }
    }
    info!("scribed stopped");
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{parse, resolve, HostFacts, Source};
    use scribe_core::platform::DefaultPaths;

    fn settings_in(dir: &std::path::Path) -> Settings {
        let text = format!("data_dir = '{}'\n[log]\nfile = ''\n", dir.display());
        let source = Source::File("test.toml".into());
        let config = parse(&text, &source, &config::context()).unwrap();
        resolve(
            config,
            source,
            &DefaultPaths::current().unwrap(),
            &HostFacts,
        )
        .unwrap()
    }

    #[test]
    fn serve_creates_folders_and_stops_on_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(serve(settings_in(&data), std::future::ready(())))
            .unwrap();
        assert!(data.is_dir());
        assert!(data.join("spool").is_dir());
    }

    #[test]
    fn serve_reports_folders_it_cannot_create() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, "").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(serve(
                settings_in(&blocker.join("data")),
                std::future::ready(()),
            ))
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("cannot create folder"),
            "{err:#}"
        );
    }

    #[test]
    fn arguments() {
        let args =
            Args::try_parse_from(["scribed", "--config", "/etc/x.toml", "--check-config"]).unwrap();
        assert_eq!(
            args.config.as_deref(),
            Some(std::path::Path::new("/etc/x.toml"))
        );
        assert!(args.check_config);
        assert!(Args::try_parse_from(["scribed", "--bogus"]).is_err());
    }

    #[test]
    fn config_errors_exit_with_2() {
        let code = run(
            Args::try_parse_from(["scribed", "--config", "/nonexistent/scribe.toml"]).unwrap(),
            None,
            None,
        );
        assert_eq!(code, ExitCode::from(EXIT_CONFIG));
    }
}
