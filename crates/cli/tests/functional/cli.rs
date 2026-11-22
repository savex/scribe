//! Functional tests for `scribe_cli` (moved from `src/lib.rs`).

use clap::Parser;
use scribe_cli::*;
use scribe_core::Mode;
use std::process::ExitCode;

fn parse(args: &[&str]) -> Command {
    let mut full = vec!["scribe"];
    full.extend_from_slice(args);
    Cli::try_parse_from(full).unwrap().command
}

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
