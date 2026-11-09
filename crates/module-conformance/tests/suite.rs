//! The suite passes for well-behaved modules and catches every injected fault.

use std::time::Duration;

use scribe_module_api::Reload;
use scribe_module_conformance::{run_module_suite, BadConfig, ModuleCase};
use scribe_test_support::{Fault, MisbehavingModule, NoopModule, TagModule, TicksModule};

fn tag_case() -> ModuleCase {
    let mut case = ModuleCase::new(|| Box::new(TagModule::default()));
    case.config = "mode = \"learn\"\n[modules.tag]\nlabel = \"seen\"\n";
    case.reload = Some((
        "[modules.tag]\nlabel = \"seen\"\nstrict = true\n",
        Reload::NeedsRestart(vec!["modules.tag.strict".into()]),
    ));
    case.bad_configs = vec![
        BadConfig {
            text: "[modules.tag]\nlabel = \"x\"\nlabels = 1\n",
            line: 3,
            contains: "unknown field `labels`",
        },
        BadConfig {
            text: "\n[modules.tag]\n\nlabel = \"\"\n",
            line: 4,
            contains: "label must not be empty",
        },
    ];
    case
}

#[test]
fn a_flow_hook_module_passes() {
    run_module_suite(&tag_case()).unwrap();
}

#[test]
fn a_source_module_passes() {
    let mut case = ModuleCase::new(|| Box::new(TicksModule::new()));
    case.config = "[modules.ticks]\nevery = \"30s\"\n";
    case.reload = Some((
        "[modules.ticks]\nevery = \"1m\"\n",
        Reload::NeedsRestart(vec!["modules.ticks.every".into()]),
    ));
    case.bad_configs = vec![BadConfig {
        text: "[modules.ticks]\nevery = \"soon\"\n",
        line: 2,
        contains: "soon",
    }];
    run_module_suite(&case).unwrap();
}

#[test]
fn a_module_without_outputs_passes() {
    run_module_suite(&ModuleCase::new(|| Box::new(NoopModule::default()))).unwrap();
}

fn failures_for(fault: Fault) -> Vec<String> {
    let mut case = tag_case();
    case.make = Box::new(move || Box::new(MisbehavingModule::new(fault)));
    case.hook_budget = Duration::from_millis(5);
    case.fuzz_runs = 50;
    run_module_suite(&case).expect_err("the suite must catch the fault")
}

#[test]
fn catches_every_fault() {
    let cases = [
        (Fault::BadManifest, "must be named 'tag.<name>'"),
        (Fault::PanicsOnPayload, "flow hook panicked"),
        (
            Fault::UndeclaredRecord,
            "undeclared record kind 'tag.undeclared'",
        ),
        (Fault::IgnoresPause, "while paused"),
        (Fault::AcceptsBadConfig, "must fail with a config error"),
        (Fault::Slow, "per flow, budget"),
        (Fault::NoRestart, "cannot start again after stop"),
    ];
    for (fault, expected) in cases {
        let failures = failures_for(fault);
        assert!(
            failures.iter().any(|f| f.contains(expected)),
            "{fault:?}: expected a failure containing {expected:?}, got {failures:#?}"
        );
    }
}
