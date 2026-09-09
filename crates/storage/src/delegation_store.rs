use appport_auth_mesh_contract::{Delegation, DelegationId, PrincipalId, TenantContext};

use crate::StorageError;

/// Durable delegations.
///
/// A delegation is tenant-bound, capability-scoped, time-bound and revocable;
/// the store refuses to persist one that is not.
pub trait DelegationStore {
    fn create_delegation(&self, delegation: Delegation) -> Result<Delegation, StorageError>;

    fn get_delegation(
        &self,
        tenant: &TenantContext,
        delegation_id: &DelegationId,
    ) -> Result<Option<Delegation>, StorageError>;

    fn list_delegations_for_delegate(
        &self,
        tenant: &TenantContext,
        delegate: &PrincipalId,
    ) -> Result<Vec<Delegation>, StorageError>;

    fn revoke_delegation(
        &self,
        tenant: &TenantContext,
        delegation_id: &DelegationId,
        revoked_at: i64,
    ) -> Result<(), StorageError>;
}
