use appport_auth_mesh_contract::{
    AgentState, Claims, Principal, PrincipalId, ProviderName, ProviderSubject, TenantContext,
};

use crate::StorageError;

/// A proven external identity bound to an AuthPort principal.
///
/// ```text
/// Google  subject 12345  ─┐
/// GitHub  subject 98765  ─┴─>  principal_abc
/// ```
///
/// The external system establishes identity; the application owns the
/// principal. Several bindings may point at one principal — that is account
/// linking — but a binding never points at two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalBinding {
    pub tenant_id: appport_auth_mesh_contract::TenantId,
    pub connector: ProviderName,
    pub external_subject: ProviderSubject,
    pub principal_id: PrincipalId,
    pub linked_at: i64,
}

/// The principal registry.
///
/// It enforces the uniqueness invariant `(tenant_id, connector,
/// external_subject) -> exactly one principal`, and every read is
/// tenant-scoped.
pub trait PrincipalStore {
    fn put_principal(&self, principal: Principal) -> Result<(), StorageError>;

    fn get_principal(
        &self,
        tenant: &TenantContext,
        principal_id: &PrincipalId,
    ) -> Result<Option<Principal>, StorageError>;

    fn list_principals(&self, tenant: &TenantContext) -> Result<Vec<Principal>, StorageError>;

    fn set_agent_state(
        &self,
        tenant: &TenantContext,
        principal_id: &PrincipalId,
        state: AgentState,
    ) -> Result<(), StorageError>;

    fn update_claims(
        &self,
        tenant: &TenantContext,
        principal_id: &PrincipalId,
        claims: Claims,
    ) -> Result<(), StorageError>;

    /// Bind an external identity to an existing principal.
    ///
    /// Idempotent for an identical binding; an attempt to move a bound external
    /// identity to a different principal is refused.
    fn bind_external_identity(
        &self,
        tenant: &TenantContext,
        connector: &ProviderName,
        external_subject: &ProviderSubject,
        principal_id: &PrincipalId,
        linked_at: i64,
    ) -> Result<ExternalBinding, StorageError>;

    fn resolve_external_identity(
        &self,
        tenant: &TenantContext,
        connector: &ProviderName,
        external_subject: &ProviderSubject,
    ) -> Result<Option<PrincipalId>, StorageError>;

    fn bindings_for(
        &self,
        tenant: &TenantContext,
        principal_id: &PrincipalId,
    ) -> Result<Vec<ExternalBinding>, StorageError>;
}
