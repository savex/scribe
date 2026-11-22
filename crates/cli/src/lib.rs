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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["scribe"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    mod smoke {
        use super::*;

        #[test]
        fn definition_is_valid() {
            Cli::command().debug_assert();
        }
    }

    mod functional {
        use super::*;

        #[test]
        fn parses_every_command() {
            assert_eq!(parse(&["status"]), Command::Status);
            assert_eq!(parse(&["hosts"]), Command::Hosts);
            assert_eq!(
                parse(&["mode", "caution"]),
                Command::Mode {
                    mode: Mode::Caution
                }
            );
            assert_eq!(
                parse(&["mode", "ALERT"]),
                Command::Mode { mode: Mode::Alert }
            );
            assert_eq!(parse(&["alerts"]), Command::Alerts { action: None });
            assert_eq!(
                parse(&["alerts", "ack", "42"]),
                Command::Alerts {
                    action: Some(AlertsAction::Ack { id: 42 })
                }
            );
            assert_eq!(
                parse(&["baseline", "add", "api.example.com"]),
                Command::Baseline {
                    action: BaselineAction::Add {
                        host: "api.example.com".into()
                    }
                }
            );
            assert_eq!(
                parse(&["baseline", "remove", "api.example.com"]),
                Command::Baseline {
                    action: BaselineAction::Rm {
                        host: "api.example.com".into()
                    }
                }
            );
            assert_eq!(parse(&["export"]), Command::Export);
            assert_eq!(parse(&["version"]), Command::Version);
        }

        #[test]
        fn rejects_bad_input() {
            let err = Cli::try_parse_from(["scribe", "mode", "paranoid"]).unwrap_err();
            assert!(err.to_string().contains("unknown mode 'paranoid'"), "{err}");
            assert!(Cli::try_parse_from(["scribe", "alerts", "ack", "x"]).is_err());
            assert!(Cli::try_parse_from(["scribe", "baseline"]).is_err());
            assert!(Cli::try_parse_from(["scribe", "frobnicate"]).is_err());
        }

        #[test]
        fn describes_commands_as_typed() {
            for args in [
                vec!["status"],
                vec!["mode", "learn"],
                vec!["alerts", "ack", "7"],
                vec!["baseline", "rm", "x.example"],
                vec!["export"],
            ] {
                assert_eq!(parse(&args).describe(), args.join(" "));
            }
        }

        #[test]
        fn exit_codes() {
            assert_eq!(
                run(Cli {
                    command: Command::Version
                }),
                ExitCode::SUCCESS
            );
            assert_eq!(
                run(Cli {
                    command: Command::Hosts
                }),
                ExitCode::from(EXIT_FAILURE)
            );
        }
    }
}
