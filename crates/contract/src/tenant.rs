#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    pub id: crate::TenantId,
    pub namespace: String,
    pub policy_id: crate::PolicyId,
    pub storage_root_id: crate::StorageRootId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    pub tenant_id: crate::TenantId,
    pub namespace: String,
    pub policy_id: crate::PolicyId,
    pub storage_root_id: crate::StorageRootId,
}

impl From<Tenant> for TenantContext {
    fn from(tenant: Tenant) -> Self {
        Self {
            tenant_id: tenant.id,
            namespace: tenant.namespace,
            policy_id: tenant.policy_id,
            storage_root_id: tenant.storage_root_id,
        }
    }
}

impl From<&Tenant> for TenantContext {
    fn from(tenant: &Tenant) -> Self {
        Self {
            tenant_id: tenant.id.clone(),
            namespace: tenant.namespace.clone(),
            policy_id: tenant.policy_id.clone(),
            storage_root_id: tenant.storage_root_id.clone(),
        }
    }
}
