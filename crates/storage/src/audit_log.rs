use std::collections::HashMap;

use appport_auth_mesh_contract::TenantContext;

use crate::StorageError;

pub trait AuditLog {
    fn record_event(&self, tenant: &TenantContext, event: AuditEvent) -> Result<(), StorageError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub tenant_id: String,
    pub identity_id: Option<String>,
    pub kind: String,
    pub timestamp: i64,
    pub metadata: HashMap<String, String>,
}
