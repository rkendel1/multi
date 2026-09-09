use appport_auth_mesh_contract::TenantContext;

use crate::StorageError;

pub trait SessionStore {
    fn create_session(
        &self,
        tenant: &TenantContext,
        identity_id: &str,
        device_info: Option<String>,
    ) -> Result<Session, StorageError>;

    fn revoke_session(&self, tenant: &TenantContext, session_id: &str) -> Result<(), StorageError>;

    fn list_sessions(
        &self,
        tenant: &TenantContext,
        identity_id: &str,
    ) -> Result<Vec<Session>, StorageError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub identity_id: String,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}
