use appport_auth_mesh_contract::{Claims, Identity};

use crate::StorageError;

pub trait IdentityStore {
    fn link_account(
        &self,
        tenant_id: &str,
        provider: &str,
        provider_subject: &str,
    ) -> Result<Identity, StorageError>;

    fn get_identity(&self, identity_id: &str) -> Result<Option<Identity>, StorageError>;

    fn update_claims(&self, identity_id: &str, claims: Claims) -> Result<(), StorageError>;
}
