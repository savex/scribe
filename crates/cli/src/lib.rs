//! `scribe` — command line client. Talks to `scribed` over the local API (specs 6.2, 6.3).
//!
//! Exit codes: 0 success, 1 failure (scribed unreachable, permission denied, a refused call,
//! `daemon health` unhealthy), 2 usage error.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use scribe_core::{HumanDuration, Mode, VERSION};

mod client;
mod commands;
pub mod output;

pub use client::{socket_path, Failure};

pub const EXIT_FAILURE: u8 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "scribe",
    version = VERSION,
    about = "Command line client for scribed",
    arg_required_else_help = true
)]
pub struct Cli {
    /// scribed's API socket (default: SCRIBE_SOCKET, else the OS default)
    #[arg(long, global = true, value_name = "PATH")]
    pub socket: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Daemon, sensor and storage health; current mode and profile (= `daemon status`)
    Status(StatusArgs),
    /// Tracked hosts with counters and flags
    Hosts {
        /// Only hosts whose name contains this text
        #[arg(long, value_name = "TEXT")]
        filter: Option<String>,
        /// Print JSON
        #[arg(long)]
        json: bool,
    },
    /// Switch the policy mode
    Mode {
        /// learn, caution or alert
        #[arg(value_parser = parse_mode)]
        mode: Mode,
    },
    /// List alerts with their notes, or acknowledge one
    Alerts {
        #[command(subcommand)]
        action: Option<AlertsAction>,
        /// Print JSON
        #[arg(long)]
        json: bool,
    },
    /// List or edit the baseline (known hosts) of the active profile
    Baseline {
        #[command(subcommand)]
        action: Option<BaselineAction>,
        /// Print JSON
        #[arg(long)]
        json: bool,
    },
    /// Dump hosts and baseline as JSON
    Export {
        /// Write to this file (created 0600) instead of standard output
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Modules built into scribed: id, version, enabled, state, health, drops
    Modules {
        /// Print JSON
        #[arg(long)]
        json: bool,
    },
    /// Inspect and control the running scribed
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    /// Print the version
    Version,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct StatusArgs {
    /// Print JSON (one object per line with --watch)
    #[arg(long)]
    pub json: bool,
    /// Redraw every interval, e.g. 2s, until Ctrl-C
    #[arg(long, value_name = "INTERVAL", value_parser = parse_duration)]
    pub watch: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum AlertsAction {
    /// Acknowledge an alert so it stops repeating
    Ack { id: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum BaselineAction {
    /// Add hosts to the baseline
    Add {
        #[arg(required = true)]
        hosts: Vec<String>,
    },
    /// Remove hosts from the baseline
    #[command(alias = "remove")]
    Rm {
        #[arg(required = true)]
        hosts: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum DaemonCommand {
    /// Run state and live counters, critical metrics first
    Status(StatusArgs),
    /// healthy / degraded / unhealthy for scripts; exit 1 when unhealthy or unreachable
    Health {
        /// Print JSON
        #[arg(long)]
        json: bool,
        /// Give up after this long
        #[arg(long, value_name = "DURATION", default_value = "2s", value_parser = parse_duration)]
        timeout: Duration,
    },
    /// Zero runtime counters, clear caches, reload the config (all three without a flag)
    Reset {
        /// Zero the counters `status` shows (stored history is never touched)
        #[arg(long)]
        counters: bool,
        /// Write pending batches, then clear the host and DNS caches
        #[arg(long)]
        caches: bool,
        /// Re-read the config file and apply what can change live
        #[arg(long)]
        config: bool,
    },
    /// Stop processing for a while; it always wakes up on its own
    #[command(visible_alias = "hybernate", alias = "sleep")]
    Hibernate {
        /// How long, e.g. 30m (at most daemon.max_hibernate, which is also the default)
        #[arg(long = "for", value_name = "DURATION", value_parser = parse_duration)]
        for_: Option<Duration>,
    },
    /// Resume processing
    #[command(alias = "wake")]
    Wakeup,
}

fn parse_mode(s: &str) -> Result<Mode, String> {
    s.parse()
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    s.parse::<HumanDuration>()
        .map(Duration::from)
        .map_err(|e| e.to_string())
}

impl Command {
    /// The command as a user would type it, for messages.
    pub fn describe(&self) -> String {
        match self {
            Command::Status(_) => "status".into(),
            Command::Hosts { .. } => "hosts".into(),
            Command::Mode { mode } => format!("mode {mode}"),
            Command::Alerts { action: None, .. } => "alerts".into(),
            Command::Alerts {
                action: Some(AlertsAction::Ack { id }),
                ..
            } => format!("alerts ack {id}"),
            Command::Baseline { action: None, .. } => "baseline".into(),
            Command::Baseline {
                action: Some(BaselineAction::Add { hosts }),
                ..
            } => format!("baseline add {}", hosts.join(" ")),
            Command::Baseline {
                action: Some(BaselineAction::Rm { hosts }),
                ..
            } => format!("baseline rm {}", hosts.join(" ")),
            Command::Export { .. } => "export".into(),
            Command::Modules { .. } => "modules".into(),
            Command::Daemon { command } => format!(
                "daemon {}",
                match command {
                    DaemonCommand::Status(_) => "status",
                    DaemonCommand::Health { .. } => "health",
                    DaemonCommand::Reset { .. } => "reset",
                    DaemonCommand::Hibernate { .. } => "hibernate",
                    DaemonCommand::Wakeup => "wakeup",
                }
            ),
            Command::Version => "version".into(),
        }
    }
}

/// Entry point of the `scribe` binary.
pub fn main() -> ExitCode {
    run(Cli::parse(), std::env::var_os(scribe_api::SOCKET_ENV))
}

/// Runs one command; `socket_env` is the value of `SCRIBE_SOCKET`.
pub fn run(cli: Cli, socket_env: Option<OsString>) -> ExitCode {
    if cli.command == Command::Version {
        println!("scribe {VERSION}");
        return ExitCode::SUCCESS;
    }
    let socket = socket_path(cli.socket.clone(), socket_env);
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("scribe: cannot start: {e}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    match runtime.block_on(commands::run(&cli.command, &socket)) {
        Ok(code) => code,
        Err(failure) => {
            eprintln!("scribe: {}", failure.message);
            ExitCode::from(failure.code)
        }
    }
}
