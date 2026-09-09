use appport_auth_mesh_contract::{
    Claims, Identity, IdentityId, ProviderName, ProviderSubject, TenantContext,
};

use crate::StorageError;

pub trait IdentityStore {
    fn link_account(
        &self,
        tenant: &TenantContext,
        provider: &ProviderName,
        provider_subject: &ProviderSubject,
    ) -> Result<Identity, StorageError>;

    fn get_identity(
        &self,
        tenant: &TenantContext,
        identity_id: &IdentityId,
    ) -> Result<Option<Identity>, StorageError>;

    fn find_identity(
        &self,
        tenant: &TenantContext,
        provider: &ProviderName,
        provider_subject: &ProviderSubject,
    ) -> Result<Option<Identity>, StorageError>;

    fn update_claims(
        &self,
        tenant: &TenantContext,
        identity_id: &IdentityId,
        claims: Claims,
    ) -> Result<(), StorageError>;
}
