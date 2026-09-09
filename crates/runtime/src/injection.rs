use std::collections::HashMap;

use appport_auth_mesh_authz::{evaluate, Condition, Policy, Rule};
use appport_auth_mesh_contract::{Claims, ContractVersion, Identity, OfflineSemantics, Tenant};
use appport_auth_mesh_dsl::AuthConfig;

use crate::{capability_envelope::CapabilityEnvelope, context::RuntimeContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingRequest {
    pub host: String,
    pub headers: HashMap<String, String>,
    pub auth_subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthError {
    pub message: String,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AuthError {}

pub fn inject_auth_context(
    auth_config: &AuthConfig,
    request: &IncomingRequest,
) -> Result<RuntimeContext, AuthError> {
    let tenant_id = resolve_tenant(auth_config, request)?;
    let provider = auth_config
        .providers
        .first()
        .cloned()
        .ok_or_else(|| AuthError {
            message: "at least one provider is required".to_string(),
        })?;
    let subject = request
        .auth_subject
        .clone()
        .or_else(|| request.headers.get("x-auth-subject").cloned())
        .ok_or_else(|| AuthError {
            message: "missing auth subject".to_string(),
        })?;

    let claims = Claims {
        values: HashMap::new(),
    };
    let identity = Identity {
        id: format!("{}:{}:{}", tenant_id, provider, subject),
        provider,
        tenant_id: tenant_id.clone(),
        claims: claims.clone(),
        version: ContractVersion { major: 1, minor: 0 },
        offline: OfflineSemantics {
            max_age_seconds: 300,
            must_revalidate: true,
        },
    };
    let tenant = Tenant {
        id: tenant_id.clone(),
        namespace: tenant_id.clone(),
        policy_id: format!("{}-default-policy", tenant_id),
        storage_root_id: format!("{}-root", tenant_id),
    };

    let policy = Policy {
        id: tenant.policy_id.clone(),
        rules: vec![Rule {
            capability: "storage.read".to_string(),
            condition: Condition::TimeBound {
                start: 0,
                end: i64::MAX,
            },
        }],
    };
    let capability_envelope: CapabilityEnvelope = evaluate(&policy, &identity, &tenant);

    Ok(RuntimeContext {
        identity: Some(identity),
        tenant: Some(tenant),
        claims: Some(claims),
        capability_envelope,
    })
}

fn resolve_tenant(auth_config: &AuthConfig, request: &IncomingRequest) -> Result<String, AuthError> {
    if let Some(v) = request.headers.get("x-tenant-id") {
        if !v.trim().is_empty() {
            return Ok(v.clone());
        }
    }

    if auth_config.multi_tenant {
        if let Some((subdomain, _)) = request.host.split_once('.') {
            if !subdomain.is_empty() {
                return Ok(subdomain.to_string());
            }
        }
        return Err(AuthError {
            message: "unable to resolve tenant for multi-tenant auth".to_string(),
        });
    }

    Ok("default".to_string())
}
