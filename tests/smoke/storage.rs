//! The default storage opens.

use scribe_storage_api::Health;
use scribe_storage_conformance::block_on;
use scribe_storage_manager::{Registry, StorageConfig, StorageManager};

#[test]
fn sqlite_opens_and_reports_healthy() {
    let registry = Registry::with_builtin();
    assert!(registry.kinds().any(|k| k == "sqlite"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scribe.db");
    let config = StorageConfig::sqlite_default(path.to_str().unwrap());
    let manager = StorageManager::from_config(&registry, &config).unwrap();
    block_on(manager.migrate()).unwrap();
    assert!(path.is_file());
    assert_eq!(block_on(manager.state().health()), Health::Ok);
}
