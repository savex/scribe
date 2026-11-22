//! Functional tests for `scribe_daemon::modules` (moved from `src/modules/mod.rs`).

use scribe_daemon::modules::*;

#[cfg(feature = "url")]
#[test]
fn url_module_declares_its_record_kind() {
    let url = builtin().into_iter().find(|s| s.id == "url").unwrap();
    assert_eq!(url.record_kinds(), ["url.request"]);
    assert!(format!("{url:?}").contains("url"));
}
