use appport_auth_mesh_contract::{AgentState, Capability, Delegation, Principal, PrincipalKind, TenantContext};

use crate::policy::{
    AuthorizationDecision, CapabilityEnvelope, Condition, DenialReason, GrantedCapability, Policy,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluationError {
    pub message: String,
}

impl std::fmt::Display for PolicyEvaluationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PolicyEvaluationError {}

pub fn evaluate(
    policy: &Policy,
    principal: &Principal,
    tenant: &TenantContext,
) -> Result<CapabilityEnvelope, PolicyEvaluationError> {
    if principal.tenant_id != tenant.tenant_id {
        return Err(PolicyEvaluationError {
            message: "principal tenant does not match tenant context".to_string(),
        });
    }

    if policy.id != tenant.policy_id {
        return Err(PolicyEvaluationError {
            message: "policy does not match tenant context".to_string(),
        });
    }

    let mut granted_capabilities = Vec::new();

    for rule in &policy.rules {
        if condition_matches(&rule.condition, principal) {
            granted_capabilities.push(GrantedCapability {
                capability: rule.capability.clone(),
                policy_id: policy.id.clone(),
                tenant_id: tenant.tenant_id.clone(),
                principal_id: principal.id.clone(),
                claim_basis: claim_basis(&rule.condition),
                delegation_id: None,
            });
        }
    }

    Ok(CapabilityEnvelope {
        granted_capabilities,
    })
}

pub fn evaluate_capability(
    policy: Option<&Policy>,
    principal: Option<&Principal>,
    tenant: Option<&TenantContext>,
    delegation: Option<&Delegation>,
    capability: &Capability,
    now: i64,
) -> AuthorizationDecision {
    let policy = match policy {
        Some(policy) => policy,
        None => return deny(DenialReason::PolicyNotFound),
    };
    let principal = match principal {
        Some(principal) => principal,
        None => return deny(DenialReason::UnknownPrincipal),
    };
    let tenant = match tenant {
        Some(tenant) => tenant,
        None => return deny(DenialReason::UnknownTenant),
    };

    if principal.tenant_id != tenant.tenant_id || policy.id != tenant.policy_id {
        return deny(DenialReason::TenantMismatch);
    }

    if principal.kind == PrincipalKind::Agent {
        match principal.agent_state {
            Some(AgentState::Active) => {}
            Some(AgentState::Revoked | AgentState::Retired) => return deny(DenialReason::AgentRevoked),
            Some(AgentState::Suspended) => return deny(DenialReason::AgentSuspended),
            Some(AgentState::Created) | None => return deny(DenialReason::UnknownPrincipal),
        }
    }

    for rule in &policy.rules {
        if &rule.capability == capability && condition_matches(&rule.condition, principal) {
            return AuthorizationDecision::Allow {
                grant: GrantedCapability {
                    capability: capability.clone(),
                    policy_id: policy.id.clone(),
                    tenant_id: tenant.tenant_id.clone(),
                    principal_id: principal.id.clone(),
                    claim_basis: claim_basis(&rule.condition),
                    delegation_id: None,
                },
                audit_event_id: None,
            };
        }
    }

    if principal.kind == PrincipalKind::Agent {
        let delegation = match delegation {
            Some(delegation) => delegation,
            None => return deny(DenialReason::CapabilityNotGranted),
        };
        if delegation.tenant_id != tenant.tenant_id || delegation.delegate != principal.id {
            return deny(DenialReason::InvalidDelegation);
        }
        if delegation.revoked_at.is_some() {
            return deny(DenialReason::RevokedDelegation);
        }
        if !delegation.is_valid_at(now) {
            return deny(DenialReason::ExpiredDelegation);
        }
        if !delegation.capabilities.iter().any(|c| c == capability) {
            return deny(DenialReason::CapabilityNotGranted);
        }
        return AuthorizationDecision::Allow {
            grant: GrantedCapability {
                capability: capability.clone(),
                policy_id: policy.id.clone(),
                tenant_id: tenant.tenant_id.clone(),
                principal_id: principal.id.clone(),
                claim_basis: vec![format!("delegation:{}", delegation.delegator)],
                delegation_id: Some(delegation.id.clone()),
            },
            audit_event_id: None,
        };
    }

    deny(DenialReason::CapabilityNotGranted)
}

fn deny(reason: DenialReason) -> AuthorizationDecision {
    AuthorizationDecision::Deny {
        reason,
        audit_event_id: None,
    }
}

fn condition_matches(condition: &Condition, principal: &Principal) -> bool {
    match condition {
        Condition::ClaimEquals { key, value } => principal.claims.values.get(key) == Some(value),
        Condition::ClaimIn { key, values } => principal
            .claims
            .values
            .get(key)
            .map(|v| values.contains(v))
            .unwrap_or(false),
        Condition::TimeBound { start, end } => {
            let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(v) => v.as_secs() as i64,
                Err(_) => return false,
            };
            now >= *start && now <= *end
        }
    }
}

fn claim_basis(condition: &Condition) -> Vec<String> {
    match condition {
        Condition::ClaimEquals { key, .. } | Condition::ClaimIn { key, .. } => vec![key.clone()],
        Condition::TimeBound { .. } => vec!["time".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use appport_auth_mesh_contract::{
        ClaimValue, Claims, ContractVersion, Principal, PrincipalId, PrincipalKind, TenantContext,
    };

    use crate::{
        evaluator::evaluate,
        policy::{Condition, Policy, Rule},
    };

    #[test]
    fn grants_capability_when_claim_matches() {
        let mut claims = HashMap::new();
        claims.insert("role".to_string(), ClaimValue::Enum("admin".to_string()));
        let principal = Principal {
            id: PrincipalId("id-1".to_string()),
            kind: PrincipalKind::Human,
            tenant_id: "tenant-a".into(),
            claims: Claims { values: claims },
            version: ContractVersion { major: 1, minor: 0 },
            agent_state: None,
        };
        let tenant = TenantContext {
            tenant_id: "tenant-a".into(),
            namespace: "tenant-a".to_string(),
            policy_id: "p1".into(),
            storage_root_id: "root-a".into(),
        };
        let policy = Policy {
            id: "p1".into(),
            rules: vec![Rule {
                capability: "billing.charge".into(),
                condition: Condition::ClaimEquals {
                    key: "role".to_string(),
                    value: ClaimValue::Enum("admin".to_string()),
                },
            }],
        };

        let envelope = evaluate(&policy, &principal, &tenant).expect("policy should evaluate");
        assert_eq!(envelope.capabilities(), vec!["billing.charge".into()]);
    }

    #[test]
    fn fails_closed_when_principal_tenant_does_not_match_context() {
        let principal = Principal {
            id: PrincipalId("id-1".to_string()),
            kind: PrincipalKind::Human,
            tenant_id: "tenant-a".into(),
            claims: Claims {
                values: HashMap::new(),
            },
            version: ContractVersion { major: 1, minor: 0 },
            agent_state: None,
        };
        let tenant = TenantContext {
            tenant_id: "tenant-b".into(),
            namespace: "tenant-b".to_string(),
            policy_id: "p1".into(),
            storage_root_id: "root-b".into(),
        };
        let policy = Policy {
            id: "p1".into(),
            rules: vec![Rule {
                capability: "storage.read".into(),
                condition: Condition::TimeBound {
                    start: 0,
                    end: i64::MAX,
                },
            }],
        };

        let err = evaluate(&policy, &principal, &tenant).expect_err("tenant mismatch must fail");
        assert_eq!(err.message, "principal tenant does not match tenant context");
    }
}
