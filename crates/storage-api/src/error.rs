use std::fmt;

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug)]
pub enum StorageError {
    /// The backend does not support this operation (see its capabilities).
    Unsupported(&'static str),
    /// The operation is planned but not written yet.
    NotImplemented(&'static str),
    Config(String),
    Backend(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Unsupported(op) => write!(f, "operation not supported by backend: {op}"),
            StorageError::NotImplemented(op) => write!(f, "not implemented yet: {op}"),
            StorageError::Config(msg) => write!(f, "storage config error: {msg}"),
            StorageError::Backend(err) => write!(f, "storage backend error: {err}"),
        }
    }
}

impl std::error::Error for StorageError {}
