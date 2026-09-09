use appport_auth_mesh_contract::{StorageRootId, TenantContext, TenantId};

use crate::StorageError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRoot {
    pub tenant_id: TenantId,
    pub root_id: StorageRootId,
}

pub trait TenantRootStore {
    fn put_tenant(&self, tenant: TenantContext) -> Result<(), StorageError>;
    fn get_tenant(&self, tenant_id: &TenantId) -> Result<Option<TenantContext>, StorageError>;
    fn verify_storage_root(
        &self,
        tenant: &TenantContext,
        storage_root_id: &StorageRootId,
    ) -> Result<(), StorageError>;
}
