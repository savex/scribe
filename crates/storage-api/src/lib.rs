//! Storage plugin interfaces.
//!
//! Storage is split into two roles:
//! - [`StateStore`] (exactly one): hosts, counters, baselines, alert state. Read on the hot path.
//! - [`StateStore`] also keeps each module's state (key → JSON value).
//! - [`EventSink`] (zero or more): append-only flow, alert, audit, metric and module records.
//!
//! Backends register a [`StorageFactory`] with the storage manager.

pub mod codec;
pub mod error;
pub mod model;
pub mod traits;

pub use error::{Result, StorageError};
pub use model::*;
pub use traits::*;
