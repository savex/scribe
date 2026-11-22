pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The backend does not support this operation (see its capabilities).
    #[error("operation not supported by backend: {0}")]
    Unsupported(&'static str),
    /// The operation is planned but not written yet.
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
    #[error("storage config error: {0}")]
    Config(String),
    #[error("storage backend error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A stored record or the schema can't be read by this version.
    #[error("stored data cannot be read: {0}")]
    Data(String),
}

impl StorageError {
    /// Wrap any backend error.
    pub fn backend(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        StorageError::Backend(Box::new(e))
    }
}
