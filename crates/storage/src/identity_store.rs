use appport_auth_mesh_contract::{Claims, Identity, TenantContext};

use crate::StorageError;

pub trait IdentityStore {
    fn link_account(
        &self,
        tenant: &TenantContext,
        provider: &str,
        provider_subject: &str,
    ) -> Result<Identity, StorageError>;

    fn get_identity(
        &self,
        tenant: &TenantContext,
        identity_id: &str,
    ) -> Result<Option<Identity>, StorageError>;

    fn update_claims(
        &self,
        tenant: &TenantContext,
        identity_id: &str,
        claims: Claims,
    ) -> Result<(), StorageError>;
}
