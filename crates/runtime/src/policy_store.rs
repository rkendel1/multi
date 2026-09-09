use std::collections::HashMap;
use std::sync::Mutex;

use appport_auth_mesh_authz::Policy;
use appport_auth_mesh_contract::{PolicyId, TenantContext};
use appport_auth_mesh_storage::StorageError;

/// Where a tenant's policy comes from.
///
/// Policies are looked up by the tenant's own policy id, so one tenant can
/// never be evaluated against another's rules.
pub trait PolicyStore {
    fn policy_for(&self, tenant: &TenantContext) -> Result<Option<Policy>, StorageError>;
}

#[derive(Default)]
pub struct MemoryPolicyStore {
    policies: Mutex<HashMap<PolicyId, Policy>>,
}

impl MemoryPolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&self, policy: Policy) -> Result<(), StorageError> {
        self.policies
            .lock()
            .map_err(|_| StorageError::new("policy store lock poisoned"))?
            .insert(policy.id.clone(), policy);
        Ok(())
    }
}

impl PolicyStore for MemoryPolicyStore {
    fn policy_for(&self, tenant: &TenantContext) -> Result<Option<Policy>, StorageError> {
        Ok(self
            .policies
            .lock()
            .map_err(|_| StorageError::new("policy store lock poisoned"))?
            .get(&tenant.policy_id)
            .cloned())
    }
}
