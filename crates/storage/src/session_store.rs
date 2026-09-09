use appport_auth_mesh_contract::{IdentityId, SessionId, TenantContext, TenantId};

use crate::StorageError;

pub trait SessionStore {
    fn create_session(
        &self,
        tenant: &TenantContext,
        identity_id: &IdentityId,
        expires_at: i64,
        device_info: Option<String>,
    ) -> Result<Session, StorageError>;

    fn revoke_session(
        &self,
        tenant: &TenantContext,
        session_id: &SessionId,
        revoked_at: i64,
    ) -> Result<(), StorageError>;

    fn validate_session(
        &self,
        tenant: &TenantContext,
        session_id: &SessionId,
        now: i64,
    ) -> Result<Session, StorageError>;

    fn list_sessions(
        &self,
        tenant: &TenantContext,
        identity_id: &IdentityId,
    ) -> Result<Vec<Session>, StorageError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: SessionId,
    pub identity_id: IdentityId,
    pub tenant_id: TenantId,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}
