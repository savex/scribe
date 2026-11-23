//! Command line parsing, socket choice and what errors say.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use scribe_cli::*;
use scribe_core::Mode;

fn parse(args: &[&str]) -> Command {
    let mut full = vec!["scribe"];
    full.extend_from_slice(args);
    Cli::try_parse_from(full).unwrap().command
}

#[test]
fn parses_every_command() {
    assert_eq!(parse(&["status"]), Command::Status(StatusArgs::default()));
    assert_eq!(
        parse(&["hosts", "--filter", "example", "--json"]),
        Command::Hosts {
            filter: Some("example".into()),
            hourly: None,
            since: None,
            json: true
        }
    );
    assert_eq!(
        parse(&["hosts", "--hourly", "api.example.com", "--since", "7d"]),
        Command::Hosts {
            filter: None,
            hourly: Some("api.example.com".into()),
            since: Some(Duration::from_secs(7 * 86_400)),
            json: false
        }
    );
    assert_eq!(
        parse(&["mode", "ALERT"]),
        Command::Mode { mode: Mode::Alert }
    );
    assert_eq!(
        parse(&["alerts", "ack", "42"]),
        Command::Alerts {
            action: Some(AlertsAction::Ack { id: 42 }),
            json: false
        }
    );
    assert_eq!(
        parse(&["baseline", "--json"]),
        Command::Baseline {
            action: None,
            json: true
        }
    );
    assert_eq!(
        parse(&["baseline", "add", "a.example.com", "b.example.net"]),
        Command::Baseline {
            action: Some(BaselineAction::Add {
                hosts: vec!["a.example.com".into(), "b.example.net".into()]
            }),
            json: false
        }
    );
    assert_eq!(
        parse(&["baseline", "remove", "a.example.com"]),
        Command::Baseline {
            action: Some(BaselineAction::Rm {
                hosts: vec!["a.example.com".into()]
            }),
            json: false
        }
    );
    assert_eq!(
        parse(&["export", "-o", "out.json"]),
        Command::Export {
            output: Some(PathBuf::from("out.json"))
        }
    );
    assert_eq!(parse(&["modules"]), Command::Modules { json: false });
    assert_eq!(parse(&["version"]), Command::Version);
}

#[test]
fn parses_the_daemon_commands_and_their_aliases() {
    let daemon = |command| Command::Daemon { command };
    assert_eq!(
        parse(&["daemon", "status", "--json", "--watch", "2s"]),
        daemon(DaemonCommand::Status(StatusArgs {
            json: true,
            watch: Some(Duration::from_secs(2))
        }))
    );
    assert_eq!(
        parse(&["daemon", "health"]),
        daemon(DaemonCommand::Health {
            json: false,
            timeout: Duration::from_secs(2)
        })
    );
    assert_eq!(
        parse(&["daemon", "reset", "--caches"]),
        daemon(DaemonCommand::Reset {
            counters: false,
            caches: true,
            config: false
        })
    );
    let thirty = daemon(DaemonCommand::Hibernate {
        for_: Some(Duration::from_secs(1800)),
    });
    for name in ["hibernate", "hybernate", "sleep"] {
        assert_eq!(parse(&["daemon", name, "--for", "30m"]), thirty, "{name}");
    }
    assert_eq!(
        parse(&["daemon", "hibernate"]),
        daemon(DaemonCommand::Hibernate { for_: None })
    );
    for name in ["wakeup", "wake"] {
        assert_eq!(parse(&["daemon", name]), daemon(DaemonCommand::Wakeup));
    }
}

#[test]
fn rejects_bad_input() {
    let err = Cli::try_parse_from(["scribe", "mode", "paranoid"]).unwrap_err();
    assert!(err.to_string().contains("unknown mode 'paranoid'"), "{err}");
    for args in [
        &["scribe", "alerts", "ack", "x"][..],
        &["scribe", "baseline", "add"],
        &["scribe", "frobnicate"],
        &["scribe", "daemon", "hibernate", "--for", "soon"],
        &["scribe", "daemon", "hibernate", "--for", "0s"],
        &["scribe", "status", "--watch", "2"],
        &["scribe", "hosts", "--since", "1d"],
        &["scribe", "hosts", "--hourly", "a.example", "--filter", "x"],
    ] {
        assert!(Cli::try_parse_from(args).is_err(), "{args:?}");
    }
}

#[test]
fn describes_commands_as_typed() {
    for args in [
        vec!["status"],
        vec!["mode", "learn"],
        vec!["alerts", "ack", "7"],
        vec!["baseline", "rm", "x.example"],
        vec!["export"],
        vec!["daemon", "hibernate"],
    ] {
        assert_eq!(parse(&args).describe(), args.join(" "));
    }
}

#[test]
fn the_socket_comes_from_the_flag_then_the_environment() {
    let flag = Some(PathBuf::from("/tmp/flag.sock"));
    let env = Some("/tmp/env.sock".into());
    assert_eq!(
        socket_path(flag.clone(), env.clone()),
        PathBuf::from("/tmp/flag.sock")
    );
    assert_eq!(socket_path(None, env), PathBuf::from("/tmp/env.sock"));
    assert_eq!(
        socket_path(None, Some("".into())),
        PathBuf::from(scribe_api::default_socket())
    );
    assert_eq!(
        socket_path(None, None),
        PathBuf::from(scribe_api::default_socket())
    );
    let cli = Cli::try_parse_from(["scribe", "hosts", "--socket", "/tmp/x.sock"]).unwrap();
    assert_eq!(
        cli.socket,
        Some(PathBuf::from("/tmp/x.sock")),
        "--socket is global"
    );
}

#[test]
fn version_needs_no_daemon() {
    let cli = Cli::try_parse_from(["scribe", "version"]).unwrap();
    assert_eq!(
        run(cli, Some("/nonexistent/api.sock".into())),
        std::process::ExitCode::SUCCESS
    );
}
