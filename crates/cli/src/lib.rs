//! `scribe` — command line client. Talks to `scribed` over the local API (plan phase 10);
//! until then every command except `version` reports that it isn't implemented.
//!
//! Exit codes: 0 success, 1 failure (including "not implemented yet"), 2 usage error.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use scribe_core::{Mode, VERSION};

pub const EXIT_FAILURE: u8 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "scribe",
    version = VERSION,
    about = "Command line client for scribed",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Daemon, sensor and storage health; current mode and profile
    Status,
    /// Tracked hosts with counters and flags
    Hosts,
    /// Switch the policy mode
    Mode {
        /// learn, caution or alert
        #[arg(value_parser = parse_mode)]
        mode: Mode,
    },
    /// List alerts, or acknowledge one
    Alerts {
        #[command(subcommand)]
        action: Option<AlertsAction>,
    },
    /// Edit the baseline (known hosts) of the active profile
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Dump hosts and baseline
    Export,
    /// Print the version
    Version,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum AlertsAction {
    /// Acknowledge an alert so it stops repeating
    Ack { id: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum BaselineAction {
    /// Add a host to the baseline
    Add { host: String },
    /// Remove a host from the baseline
    #[command(alias = "remove")]
    Rm { host: String },
}

fn parse_mode(s: &str) -> Result<Mode, String> {
    s.parse()
}

impl Command {
    /// The command as a user would type it, for messages.
    pub fn describe(&self) -> String {
        match self {
            Command::Status => "status".into(),
            Command::Hosts => "hosts".into(),
            Command::Mode { mode } => format!("mode {mode}"),
            Command::Alerts { action: None } => "alerts".into(),
            Command::Alerts {
                action: Some(AlertsAction::Ack { id }),
            } => format!("alerts ack {id}"),
            Command::Baseline {
                action: BaselineAction::Add { host },
            } => format!("baseline add {host}"),
            Command::Baseline {
                action: BaselineAction::Rm { host },
            } => format!("baseline rm {host}"),
            Command::Export => "export".into(),
            Command::Version => "version".into(),
        }
    }
}

/// Entry point of the `scribe` binary.
pub fn main() -> ExitCode {
    run(Cli::parse())
}

pub fn run(cli: Cli) -> ExitCode {
    match cli.command {
        Command::Version => {
            println!("scribe {VERSION}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!(
                "scribe {}: not implemented yet; the local API to scribed arrives in plan phase 10",
                other.describe()
            );
            ExitCode::from(EXIT_FAILURE)
        }
    }
}
