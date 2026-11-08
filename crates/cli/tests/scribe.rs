//! Runs the real `scribe` binary.

use std::process::Command;

const SCRIBE: &str = env!("CARGO_BIN_EXE_scribe");

fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(SCRIBE).args(args).output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn prints_its_version() {
    let expected = format!("scribe {}\n", scribe_core::VERSION);
    for args in [&["--version"][..], &["-V"], &["version"]] {
        let (code, stdout, _) = run(args);
        assert_eq!(code, Some(0), "{args:?}");
        assert_eq!(stdout, expected, "{args:?}");
    }
}

#[test]
fn commands_report_they_are_not_implemented_yet() {
    let (code, _, stderr) = run(&["mode", "caution"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("scribe mode caution: not implemented yet"),
        "{stderr}"
    );
}

#[test]
fn usage_errors_exit_with_2() {
    for args in [&[][..], &["frobnicate"], &["mode", "paranoid"]] {
        let (code, _, stderr) = run(args);
        assert_eq!(code, Some(2), "{args:?}: {stderr}");
    }
    let (_, _, stderr) = run(&["mode", "paranoid"]);
    assert!(stderr.contains("unknown mode 'paranoid'"), "{stderr}");
}
