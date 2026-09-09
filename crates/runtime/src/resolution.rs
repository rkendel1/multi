use appport_auth_mesh_authz::DenialReason;
use appport_auth_mesh_contract::{
    Claims, ContractVersion, Identity, Principal, PrincipalId, PrincipalKind, ProviderName,
    ProviderSubject, TenantContext, TenantId,
};
use appport_auth_mesh_dsl::stable_hash;
use appport_auth_mesh_providers::ExternalIdentity;
use appport_auth_mesh_storage::{ExternalBinding, IdentityStore, PrincipalStore, StorageError};

use crate::error::{AuthError, AuthLifecycleStage};

pub const CONTRACT_VERSION: ContractVersion = ContractVersion { major: 1, minor: 0 };

/// The resolution boundary.
///
/// ```text
/// (tenant, connector, external_subject)  ->  Principal
/// ```
///
/// Deterministic, so the same external identity always resolves to the same
/// principal id, and one-way: a connector can prove an external subject but can
/// never mint a principal.
pub fn principal_id_for(tenant: &TenantId, connector: &str, subject: &str) -> PrincipalId {
    let material = format!("{}|{}|{}", tenant, connector, subject);
    PrincipalId(format!("prn_{:016x}", stable_hash(material.as_bytes())))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPrincipal {
    pub principal: Principal,
    pub identity: Identity,
    pub binding: ExternalBinding,
}

/// Look up the principal an already-linked external identity belongs to.
///
/// Returns `None` when the external identity is unknown to this tenant: sign-in
/// never provisions, so an unrecognised subject is denied rather than admitted.
pub fn resolve_principal(
    identities: &dyn IdentityStore,
    principals: &dyn PrincipalStore,
    tenant: &TenantContext,
    external: &ExternalIdentity,
) -> Result<Option<ResolvedPrincipal>, AuthError> {
    let connector = ProviderName(external.connector.clone());
    let subject = ProviderSubject(external.subject.clone());

    let principal_id = principals
        .resolve_external_identity(tenant, &connector, &subject)
        .map_err(identity_error)?;
    let principal_id = match principal_id {
        Some(principal_id) => principal_id,
        None => return Ok(None),
    };

    // A binding without a principal record is a broken invariant, not a
    // reason to admit the request.
    let principal = principals
        .get_principal(tenant, &principal_id)
        .map_err(principal_error)?
        .ok_or_else(|| {
            AuthError::new(
                AuthLifecycleStage::PrincipalResolution,
                "external identity is bound to an unknown principal",
                DenialReason::UnknownPrincipal,
            )
        })?;

    let binding = principals
        .bindings_for(tenant, &principal_id)
        .map_err(principal_error)?
        .into_iter()
        .find(|binding| binding.connector == connector && binding.external_subject == subject)
        .ok_or_else(|| {
            AuthError::new(
                AuthLifecycleStage::PrincipalResolution,
                "external identity binding could not be read back",
                DenialReason::UnknownPrincipal,
            )
        })?;

    let identity = identities
        .find_identity(tenant, &connector, &subject)
        .map_err(identity_error)?
        .ok_or_else(|| {
            AuthError::new(
                AuthLifecycleStage::IdentityResolution,
                "external identity has no identity record",
                DenialReason::UnknownPrincipal,
            )
        })?;

    Ok(Some(ResolvedPrincipal {
        principal,
        identity,
        binding,
    }))
}

/// Create the principal an external identity will resolve to from now on.
pub fn provision_principal(
    identities: &dyn IdentityStore,
    principals: &dyn PrincipalStore,
    tenant: &TenantContext,
    external: &ExternalIdentity,
    kind: PrincipalKind,
    claims: Claims,
    now: i64,
) -> Result<ResolvedPrincipal, AuthError> {
    let connector = ProviderName(external.connector.clone());
    let subject = ProviderSubject(external.subject.clone());

    if principals
        .resolve_external_identity(tenant, &connector, &subject)
        .map_err(principal_error)?
        .is_some()
    {
        return Err(AuthError::new(
            AuthLifecycleStage::PrincipalResolution,
            "external identity is already linked to a principal",
            DenialReason::UnknownPrincipal,
        ));
    }

    let identity = link_identity_record(identities, tenant, &connector, &subject, claims.clone())?;
    let principal_id = principal_id_for(&tenant.tenant_id, &external.connector, &external.subject);

    let mut principal = Principal {
        id: principal_id.clone(),
        kind: kind.clone(),
        tenant_id: tenant.tenant_id.clone(),
        claims,
        version: CONTRACT_VERSION,
        agent_state: None,
    };
    if kind == PrincipalKind::Agent {
        principal.agent_state = Some(appport_auth_mesh_contract::AgentState::Active);
    }

    principals
        .put_principal(principal.clone())
        .map_err(principal_error)?;
    let binding = principals
        .bind_external_identity(tenant, &connector, &subject, &principal_id, now)
        .map_err(principal_error)?;

    Ok(ResolvedPrincipal {
        principal,
        identity,
        binding,
    })
}

/// Account linking: a second proven external identity for one principal.
///
/// ```text
/// local:alice          ─┐
/// local:alice@acme.test ┴─>  prn_…  (one principal)
/// ```
pub fn link_external_identity(
    identities: &dyn IdentityStore,
    principals: &dyn PrincipalStore,
    tenant: &TenantContext,
    principal_id: &PrincipalId,
    external: &ExternalIdentity,
    now: i64,
) -> Result<ExternalBinding, AuthError> {
    let connector = ProviderName(external.connector.clone());
    let subject = ProviderSubject(external.subject.clone());

    let principal = principals
        .get_principal(tenant, principal_id)
        .map_err(principal_error)?
        .ok_or_else(|| {
            AuthError::new(
                AuthLifecycleStage::PrincipalResolution,
                "unknown principal",
                DenialReason::UnknownPrincipal,
            )
        })?;

    if identities
        .find_identity(tenant, &connector, &subject)
        .map_err(identity_error)?
        .is_none()
    {
        link_identity_record(
            identities,
            tenant,
            &connector,
            &subject,
            principal.claims.clone(),
        )?;
    }

    principals
        .bind_external_identity(tenant, &connector, &subject, principal_id, now)
        .map_err(|err| {
            AuthError::new(
                AuthLifecycleStage::PrincipalResolution,
                err.message,
                DenialReason::UnknownPrincipal,
            )
        })
}

fn link_identity_record(
    identities: &dyn IdentityStore,
    tenant: &TenantContext,
    connector: &ProviderName,
    subject: &ProviderSubject,
    claims: Claims,
) -> Result<Identity, AuthError> {
    let identity = identities
        .link_account(tenant, connector, subject)
        .map_err(identity_error)?;
    identities
        .update_claims(tenant, &identity.id, claims)
        .map_err(identity_error)?;
    Ok(identity)
}

fn identity_error(err: StorageError) -> AuthError {
    AuthError::new(
        AuthLifecycleStage::IdentityResolution,
        err.message,
        DenialReason::UnknownPrincipal,
    )
}

fn principal_error(err: StorageError) -> AuthError {
    AuthError::new(
        AuthLifecycleStage::PrincipalResolution,
        err.message,
        DenialReason::UnknownPrincipal,
    )
}
