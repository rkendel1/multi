pub mod audit_log;
pub mod delegation_store;
pub mod identity_store;
pub mod memory;
pub mod principal_store;
pub mod session_store;
pub mod tenant_root;

pub use audit_log::{AuditEvent, AuditEventKind, AuditLog};
pub use delegation_store::DelegationStore;
pub use identity_store::IdentityStore;
pub use principal_store::{ExternalBinding, PrincipalStore};
pub use session_store::{Session, SessionStore};
pub use tenant_root::TenantRootStore;

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
