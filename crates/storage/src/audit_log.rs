use std::collections::HashMap;

use appport_auth_mesh_contract::{
    AuditEventId, DelegationId, PrincipalId, SessionId, TenantContext, TenantId,
};

use crate::StorageError;

pub trait AuditLog {
    fn record_event(&self, tenant: &TenantContext, event: AuditEvent) -> Result<(), StorageError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub event_id: AuditEventId,
    pub tenant_id: TenantId,
    pub principal_id: Option<PrincipalId>,
    pub session_id: Option<SessionId>,
    pub delegation_id: Option<DelegationId>,
    pub kind: AuditEventKind,
    pub timestamp: i64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEventKind {
    Login,
    Logout,
    SessionCreated,
    SessionRevoked,
    AccountLinked,
    ClaimsUpdated,
    AuthorizationGranted,
    AuthorizationDenied,
    DelegationCreated,
    DelegationRevoked,
    AgentCreated,
    AgentSuspended,
    AgentRevoked,
    AgentRunCreated,
    AgentRunCancelled,
}
