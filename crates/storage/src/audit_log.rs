use std::collections::HashMap;

use crate::StorageError;

pub trait AuditLog {
    fn record_event(&self, event: AuditEvent) -> Result<(), StorageError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub tenant_id: String,
    pub identity_id: Option<String>,
    pub kind: String,
    pub timestamp: i64,
    pub metadata: HashMap<String, String>,
}
