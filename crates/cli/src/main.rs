//! `scribe` — command line client. Talks to `scribed` over the local API.

use std::process::ExitCode;

use scribe_core::{Mode, VERSION};

const USAGE: &str = "usage: scribe <command>

commands:
  status               daemon, sensor and storage health
  hosts                list tracked hosts with counters
  mode <learn|caution|alert>
                       switch policy mode
  export               dump hosts and baseline
  version, --version   print version";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["version"] | ["--version"] | ["-V"] => {
            println!("scribe {VERSION}");
            ExitCode::SUCCESS
        }
        ["status"] | ["hosts"] | ["export"] => {
            eprintln!("not implemented yet: local API to scribed is pending");
            ExitCode::FAILURE
        }
        ["mode", value] => match value.parse::<Mode>() {
            Ok(mode) => {
                eprintln!("would switch to {mode}: local API to scribed is pending");
                ExitCode::FAILURE
            }
            Err(err) => {
                eprintln!("{err}");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
