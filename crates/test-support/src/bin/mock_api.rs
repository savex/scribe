//! `scribe-mock-api <scenario> <socket>`: serves a UI mock scenario (a name from
//! `ui/tests/mocks/api-scenarios/` or a path to a JSON file) until Ctrl-C, for UI development and
//! manual CLI checks (`SCRIBE_SOCKET=<socket> scribe status`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use scribe_test_support::{MockApiServer, Scenario};

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [scenario, socket] = args.as_slice() else {
        eprintln!("usage: scribe-mock-api <scenario name or file> <socket or pipe name>");
        return ExitCode::from(2);
    };
    let path = if scenario.ends_with(".json") {
        PathBuf::from(scenario)
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../ui/tests/mocks/api-scenarios")
            .join(format!("{scenario}.json"))
    };
    let loaded = match Scenario::load(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("scribe-mock-api: {e}");
            return ExitCode::from(1);
        }
    };
    if loaded.refuses_connections {
        eprintln!(
            "scribe-mock-api: {} refuses connections; nothing to serve",
            loaded.name
        );
        return ExitCode::SUCCESS;
    }
    let server = match MockApiServer::start(loaded, Path::new(socket)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("scribe-mock-api: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!("scribe-mock-api: serving {scenario} on {socket}; Ctrl-C stops");
    let _ = tokio::signal::ctrl_c().await;
    server.stop().await;
    ExitCode::SUCCESS
}
