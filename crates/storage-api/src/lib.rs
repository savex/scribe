//! Storage plugin interfaces.
//!
//! Storage is split into two roles:
//! - [`StateStore`] (exactly one): hosts, counters, baselines, alert state. Read on the hot path.
//! - [`EventSink`] (zero or more): append-only flow, alert and audit records.
//!
//! Backends register a [`StorageFactory`] with the storage manager.

pub mod error;
pub mod model;
pub mod traits;

pub use error::{Result, StorageError};
pub use model::*;
pub use traits::*;
