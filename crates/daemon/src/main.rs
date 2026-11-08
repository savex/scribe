//! `scribed` — the scribe background service.
//!
//! Runs as root / SYSTEM under systemd, launchd or the Windows Service Control Manager.
//! The logic lives in the `scribe_daemon` library; see `app.rs`.

fn main() -> std::process::ExitCode {
    scribe_daemon::app::main()
}
