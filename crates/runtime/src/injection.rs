use std::collections::HashMap;

use appport_auth_mesh_authz::{evaluate, Condition, DenialReason, Policy, Rule};
use appport_auth_mesh_contract::{
    Claims, ContractVersion, Identity, IdentityId, OfflineSemantics, Principal, PrincipalId,
    PrincipalKind, ProviderName, ProviderSubject, TenantContext,
};
use appport_auth_mesh_dsl::AuthConfig;
use appport_auth_mesh_providers::catalog;

use crate::claims::resolve_claims as resolve_declared_claims;
use crate::error::{AuthError, AuthLifecycleStage};
use crate::{capability_envelope::CapabilityEnvelope, context::RuntimeContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingRequest {
    pub host: String,
    pub headers: HashMap<String, String>,
    pub auth_subject: Option<String>,
}

pub fn inject_auth_context(
    auth_config: &AuthConfig,
    request: &IncomingRequest,
) -> Result<RuntimeContext, AuthError> {
    let tenant = resolve_tenant(request)?;
    let authenticated = authenticate_provider(auth_config, request)?;
    let mut identity = resolve_identity(&tenant, &authenticated)?;
    let session_id = validate_session(request, &identity)?;
    let claims = resolve_claims(auth_config, request)?;
    identity.claims = claims.clone();
    let principal = resolve_principal(&identity, claims.clone())?;

    let policy = Policy {
        id: tenant.policy_id.clone(),
        rules: vec![Rule {
            capability: "storage.read".into(),
            condition: Condition::TimeBound {
                start: 0,
                end: i64::MAX,
            },
        }],
    };
    let capability_envelope: CapabilityEnvelope =
        evaluate(&policy, &principal, &tenant).map_err(|err| {
            AuthError::new(
                AuthLifecycleStage::PolicyEvaluation,
                err.message,
                DenialReason::TenantMismatch,
            )
        })?;

    build_runtime_context(tenant, principal, session_id, claims, capability_envelope)
}

fn resolve_tenant(request: &IncomingRequest) -> Result<TenantContext, AuthError> {
    let header_tenant = non_empty_header(&request.headers, "x-tenant-id");
    let host_tenant = request
        .host
        .split_once('.')
        .and_then(|(subdomain, _)| non_empty(subdomain));

    let tenant_id = match (header_tenant, host_tenant) {
        (Some(header), Some(host)) if header != host => {
            return Err(auth_error(
                AuthLifecycleStage::TenantResolution,
                "ambiguous tenant resolution",
            ))
        }
        (Some(header), _) => header,
        (None, Some(host)) => host,
        (None, None) => {
            return Err(auth_error(
                AuthLifecycleStage::TenantResolution,
                "missing tenant",
            ))
        }
    };

    Ok(TenantContext {
        namespace: tenant_id.clone(),
        policy_id: format!("{}-default-policy", tenant_id).into(),
        storage_root_id: format!("{}-root", tenant_id).into(),
        tenant_id: tenant_id.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthenticatedProvider {
    provider: String,
    subject: String,
}

fn authenticate_provider(
    auth_config: &AuthConfig,
    request: &IncomingRequest,
) -> Result<AuthenticatedProvider, AuthError> {
    let provider = non_empty_header(&request.headers, "x-auth-provider").ok_or_else(|| {
        auth_error(
            AuthLifecycleStage::ProviderAuthentication,
            "missing auth provider",
        )
    })?;

    if !auth_config.declares_provider(&provider) {
        return Err(auth_error(
            AuthLifecycleStage::ProviderAuthentication,
            "auth provider is not configured for this tenant",
        ));
    }

    // Declared is not implemented: a connector without a working flow can never
    // authenticate a request.
    if !catalog::describe(&provider).status.is_supported() {
        return Err(auth_error(
            AuthLifecycleStage::ConnectorResolution,
            format!("connector `{}` is declared but not implemented", provider),
        ));
    }

    let header_subject = non_empty_header(&request.headers, "x-auth-subject");
    let request_subject = request.auth_subject.as_deref().and_then(non_empty);
    let subject = match (request_subject, header_subject) {
        (Some(request_subject), Some(header_subject)) if request_subject != header_subject => {
            return Err(auth_error(
                AuthLifecycleStage::ProviderAuthentication,
                "ambiguous auth subject",
            ))
        }
        (Some(request_subject), _) => request_subject,
        (None, Some(header_subject)) => header_subject,
        (None, None) => {
            return Err(auth_error(
                AuthLifecycleStage::ProviderAuthentication,
                "missing auth subject",
            ))
        }
    };

    Ok(AuthenticatedProvider { provider, subject })
}

fn resolve_identity(
    tenant: &TenantContext,
    authenticated: &AuthenticatedProvider,
) -> Result<Identity, AuthError> {
    Ok(Identity {
        id: IdentityId(format!(
            "{}:{}:{}",
            tenant.tenant_id, authenticated.provider, authenticated.subject
        )),
        provider: ProviderName(authenticated.provider.clone()),
        provider_subject: ProviderSubject(authenticated.subject.clone()),
        tenant_id: tenant.tenant_id.clone(),
        claims: Claims {
            values: HashMap::new(),
        },
        version: ContractVersion { major: 1, minor: 0 },
        offline: OfflineSemantics {
            max_age_seconds: 300,
            must_revalidate: true,
        },
    })
}

fn resolve_principal(identity: &Identity, claims: Claims) -> Result<Principal, AuthError> {
    let kind = match identity.provider.as_str() {
        "agent" => PrincipalKind::Agent,
        "service" => PrincipalKind::Service,
        _ => PrincipalKind::Human,
    };
    Ok(Principal {
        id: PrincipalId(identity.id.to_string()),
        kind,
        tenant_id: identity.tenant_id.clone(),
        claims,
        version: identity.version.clone(),
        agent_state: None,
    })
}

fn validate_session(request: &IncomingRequest, identity: &Identity) -> Result<String, AuthError> {
    let session_id = non_empty_header(&request.headers, "x-session-id")
        .ok_or_else(|| auth_error(AuthLifecycleStage::SessionValidation, "missing session id"))?;

    if let Some(session_identity_id) = non_empty_header(&request.headers, "x-session-identity-id") {
        if session_identity_id != identity.id.to_string() {
            return Err(auth_error(
                AuthLifecycleStage::SessionValidation,
                "session identity does not match resolved identity",
            ));
        }
    }

    Ok(session_id)
}

fn resolve_claims(
    auth_config: &AuthConfig,
    request: &IncomingRequest,
) -> Result<Claims, AuthError> {
    let mut provided = std::collections::BTreeMap::new();
    for (header, value) in &request.headers {
        if let Some(name) = header.strip_prefix("x-auth-claim-") {
            provided.insert(name.to_string(), value.clone());
        }
    }
    resolve_declared_claims(auth_config, &provided)
}

fn build_runtime_context(
    tenant: TenantContext,
    principal: Principal,
    session_id: String,
    claims: Claims,
    capability_envelope: CapabilityEnvelope,
) -> Result<RuntimeContext, AuthError> {
    if principal.tenant_id != tenant.tenant_id || principal.claims != claims {
        return Err(auth_error(
            AuthLifecycleStage::RuntimeContext,
            "runtime context inputs do not match",
        ));
    }

    Ok(RuntimeContext {
        principal,
        tenant,
        session_id: Some(appport_auth_mesh_contract::SessionId(session_id)),
        delegation: None,
        claims,
        capabilities: capability_envelope,
    })
}

fn non_empty_header(headers: &HashMap<String, String>, name: &str) -> Option<String> {
    headers.get(name).and_then(|v| non_empty(v))
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn auth_error(stage: AuthLifecycleStage, message: impl Into<String>) -> AuthError {
    let denial = match stage {
        AuthLifecycleStage::TenantResolution => DenialReason::UnknownTenant,
        AuthLifecycleStage::ConnectorResolution | AuthLifecycleStage::ProviderAuthentication => {
            DenialReason::UnsupportedConnector
        }
        AuthLifecycleStage::SessionValidation => DenialReason::InvalidSession,
        AuthLifecycleStage::ClaimsResolution => DenialReason::MissingClaim,
        _ => DenialReason::UnknownPrincipal,
    };
    AuthError::new(stage, message, denial)
}

#[cfg(test)]
mod tests {
    use super::*;
    use appport_auth_mesh_contract::ClaimValue;
    use appport_auth_mesh_dsl::{ClaimDef, ClaimKind, IsolationMode};

    fn auth_config() -> AuthConfig {
        AuthConfig {
            multi_tenant: true,
            providers: vec!["local".to_string(), "google".to_string()],
            claims: vec![ClaimDef {
                name: "role".to_string(),
                kind: ClaimKind::Enum(vec!["admin".to_string(), "user".to_string()]),
            }],
            isolation: IsolationMode::Strict,
            ..AuthConfig::default()
        }
    }

    fn request(headers: &[(&str, &str)]) -> IncomingRequest {
        IncomingRequest {
            host: "tenant-a.example.com".to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            auth_subject: None,
        }
    }

    #[test]
    fn builds_runtime_context_from_explicit_lifecycle_inputs() {
        let request = request(&[
            ("x-tenant-id", "tenant-a"),
            ("x-auth-provider", "local"),
            ("x-auth-subject", "user-1"),
            ("x-session-id", "session-1"),
            ("x-auth-claim-role", "admin"),
        ]);

        let context =
            inject_auth_context(&auth_config(), &request).expect("auth lifecycle should succeed");

        assert_eq!(context.tenant.tenant_id, "tenant-a".into());
        assert_eq!(context.principal.kind, PrincipalKind::Human);
        assert_eq!(context.principal.tenant_id, "tenant-a".into());
        assert_eq!(
            context.claims.values.get("role"),
            Some(&ClaimValue::Enum("admin".to_string()))
        );
        assert_eq!(
            context.capabilities.capabilities(),
            vec!["storage.read".into()]
        );
    }

    #[test]
    fn fails_closed_when_tenant_sources_are_ambiguous() {
        let request = request(&[
            ("x-tenant-id", "tenant-b"),
            ("x-auth-provider", "local"),
            ("x-auth-subject", "user-1"),
            ("x-session-id", "session-1"),
            ("x-auth-claim-role", "admin"),
        ]);

        let err = inject_auth_context(&auth_config(), &request)
            .expect_err("tenant ambiguity must fail closed");

        assert_eq!(err.stage, AuthLifecycleStage::TenantResolution);
        assert_eq!(err.message, "ambiguous tenant resolution");
    }

    #[test]
    fn fails_closed_when_provider_is_implicit() {
        let request = request(&[
            ("x-tenant-id", "tenant-a"),
            ("x-auth-subject", "user-1"),
            ("x-session-id", "session-1"),
            ("x-auth-claim-role", "admin"),
        ]);

        let err = inject_auth_context(&auth_config(), &request)
            .expect_err("missing provider must fail closed");

        assert_eq!(err.stage, AuthLifecycleStage::ProviderAuthentication);
        assert_eq!(err.message, "missing auth provider");
    }

    #[test]
    fn fails_closed_when_session_is_missing() {
        let request = request(&[
            ("x-tenant-id", "tenant-a"),
            ("x-auth-provider", "local"),
            ("x-auth-subject", "user-1"),
            ("x-auth-claim-role", "admin"),
        ]);

        let err = inject_auth_context(&auth_config(), &request)
            .expect_err("missing session must fail closed");

        assert_eq!(err.stage, AuthLifecycleStage::SessionValidation);
        assert_eq!(err.message, "missing session id");
    }

    #[test]
    fn fails_closed_when_required_claim_is_missing() {
        let request = request(&[
            ("x-tenant-id", "tenant-a"),
            ("x-auth-provider", "local"),
            ("x-auth-subject", "user-1"),
            ("x-session-id", "session-1"),
        ]);

        let err = inject_auth_context(&auth_config(), &request)
            .expect_err("missing claim must fail closed");

        assert_eq!(err.stage, AuthLifecycleStage::ClaimsResolution);
        assert_eq!(err.message, "missing required claim `role`");
    }
}
