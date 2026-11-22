//! Functional tests for `scribe_storage_api::error` (moved from `src/error.rs`).

use scribe_storage_api::error::*;
use std::error::Error as _;

#[test]
fn messages_are_stable() {
    assert_eq!(
        StorageError::Unsupported("query").to_string(),
        "operation not supported by backend: query"
    );
    assert_eq!(
        StorageError::NotImplemented("sqlite: migrate").to_string(),
        "not implemented yet: sqlite: migrate"
    );
    assert_eq!(
        StorageError::Config("missing path".into()).to_string(),
        "storage config error: missing path"
    );
}

#[test]
fn backend_error_keeps_its_source() {
    let err = StorageError::Backend(Box::new(std::io::Error::other("disk full")));
    assert_eq!(err.to_string(), "storage backend error: disk full");
    assert_eq!(err.source().unwrap().to_string(), "disk full");
}
