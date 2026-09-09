pub mod audit_log;
pub mod identity_store;
pub mod memory;
pub mod session_store;
pub mod tenant_root;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageError {
    pub message: String,
}

impl StorageError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for StorageError {}
