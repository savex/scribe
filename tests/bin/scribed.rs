//! `scribed`, built inside `scribe-tests` so its tests can run the real daemon.
fn main() -> std::process::ExitCode {
    scribe_daemon::app::main()
}
