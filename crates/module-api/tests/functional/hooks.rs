//! Functional tests for `scribe_module_api` (moved from `src/lib.rs`).

use scribe_module_api::*;
use serde_json::json;

#[test]
fn hook_output_helpers() {
    assert_eq!(HookOutput::none(), HookOutput::default());
    let out = HookOutput::note(json!("x"));
    assert_eq!(out.note, Some(json!("x")));
    assert!(out.signals.is_empty());
}

#[test]
fn errors_read_well() {
    assert_eq!(
        ModuleError::Start("no probe host".into()).to_string(),
        "cannot start: no probe host"
    );
    assert_eq!(
        ModuleError::Unsupported("kernel probes on macOS".into()).to_string(),
        "unsupported: kernel probes on macOS"
    );
}
