use std::sync::Arc;

use appport_auth_mesh_storage::memory::{
    MemoryAuditLog, MemoryDelegationStore, MemoryIdentityStore, MemoryPrincipalStore,
    MemorySessionStore, MemoryTenantRoot,
};
use appport_auth_mesh_storage::{AuditEvent, AuditLog};

use crate::mesh::MeshStores;
use crate::policy_store::MemoryPolicyStore;

/// The in-process durable state an application gets for free.
///
/// It is the development backing for the mesh: one object to construct, and the
/// concrete stores stay reachable so an application (or a test) can seed
/// tenants and policies.
pub struct MemoryStores {
    pub tenants: Arc<MemoryTenantRoot>,
    pub identities: Arc<MemoryIdentityStore>,
    pub principals: Arc<MemoryPrincipalStore>,
    pub sessions: Arc<MemorySessionStore>,
    pub delegations: Arc<MemoryDelegationStore>,
    pub policies: Arc<MemoryPolicyStore>,
    audit: Arc<dyn AuditLog + Send + Sync>,
    memory_audit: Option<Arc<MemoryAuditLog>>,
}

impl Default for MemoryStores {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStores {
    pub fn new() -> Self {
        let memory_audit = Arc::new(MemoryAuditLog::new());
        Self {
            tenants: Arc::new(MemoryTenantRoot::new()),
            identities: Arc::new(MemoryIdentityStore::new()),
            principals: Arc::new(MemoryPrincipalStore::new()),
            sessions: Arc::new(MemorySessionStore::new()),
            delegations: Arc::new(MemoryDelegationStore::new()),
            policies: Arc::new(MemoryPolicyStore::new()),
            audit: memory_audit.clone(),
            memory_audit: Some(memory_audit),
        }
    }

    /// Same stores, but with the audit log supplied by the caller — the audit
    /// trail is part of the authority path, so it must be swappable.
    pub fn with_audit_log(audit: Arc<dyn AuditLog + Send + Sync>) -> Self {
        Self {
            audit,
            memory_audit: None,
            ..Self::new()
        }
    }

    pub fn mesh_stores(&self) -> MeshStores {
        MeshStores {
            tenants: self.tenants.clone(),
            identities: self.identities.clone(),
            principals: self.principals.clone(),
            sessions: self.sessions.clone(),
            delegations: self.delegations.clone(),
            policies: self.policies.clone(),
            audit: self.audit.clone(),
        }
    }

    /// The recorded audit trail, when the in-memory log is in use.
    pub fn audit_events(&self) -> Vec<AuditEvent> {
        self.memory_audit
            .as_ref()
            .and_then(|audit| audit.events().ok())
            .unwrap_or_default()
    }
}
