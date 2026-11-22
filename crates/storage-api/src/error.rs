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

#[cfg(test)]
mod tests {
    use super::*;
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
}
