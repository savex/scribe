//! `scribe`, built inside `scribe-tests` so its tests can run the real CLI.
fn main() -> std::process::ExitCode {
    scribe_cli::main()
}
