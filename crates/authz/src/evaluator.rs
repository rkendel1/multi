use appport_auth_mesh_contract::{
    AgentState, Capability, Delegation, Principal, PrincipalKind, TenantContext,
};

use crate::policy::{
    Action, AuthorityBasis, AuthorizationDecision, AuthorizationRequest, CapabilityEnvelope,
    Condition, DenialReason, Effect, GrantedCapability, Policy, PrincipalAttribute,
    ResourceAttributes,
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
    evaluate_with_delegations(policy, principal, tenant, &[], i64::MIN)
}

/// The single policy engine for every principal kind.
///
/// A human's authority comes from their claims; an agent's comes from its own
/// claims *and* from live delegations. Both produce the same envelope shape,
/// and both retain provenance.
pub fn evaluate_with_delegations(
    policy: &Policy,
    principal: &Principal,
    tenant: &TenantContext,
    delegations: &[Delegation],
    now: i64,
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

    // An agent that is not active carries no authority at all, whatever its
    // delegator still holds.
    if principal.kind == PrincipalKind::Agent && principal.agent_state != Some(AgentState::Active) {
        return Ok(CapabilityEnvelope::empty());
    }

    let mut granted_capabilities = Vec::new();

    for rule in &policy.rules {
        if condition_matches(&rule.condition, principal) {
            granted_capabilities.push(GrantedCapability {
                capability: rule.capability.clone(),
                policy_id: policy.id.clone(),
                tenant_id: tenant.tenant_id.clone(),
                principal_id: principal.id.clone(),
                principal_kind: principal.kind.clone(),
                authority: AuthorityBasis::Claim,
                claim_basis: claim_basis(&rule.condition),
                delegation_id: None,
                delegated_by: None,
            });
        }
    }

    for delegation in delegations {
        if delegation.tenant_id != tenant.tenant_id
            || delegation.delegate != principal.id
            || !delegation.is_valid_at(now)
        {
            continue;
        }
        for capability in &delegation.capabilities {
            if granted_capabilities
                .iter()
                .any(|grant| &grant.capability == capability)
            {
                continue;
            }
            granted_capabilities.push(delegated_grant(
                policy, principal, tenant, delegation, capability,
            ));
        }
    }

    Ok(CapabilityEnvelope {
        granted_capabilities,
    })
}

fn delegated_grant(
    policy: &Policy,
    principal: &Principal,
    tenant: &TenantContext,
    delegation: &Delegation,
    capability: &Capability,
) -> GrantedCapability {
    GrantedCapability {
        capability: capability.clone(),
        policy_id: policy.id.clone(),
        tenant_id: tenant.tenant_id.clone(),
        principal_id: principal.id.clone(),
        principal_kind: principal.kind.clone(),
        authority: AuthorityBasis::Delegated,
        claim_basis: vec![format!("delegation:{}", delegation.delegator)],
        delegation_id: Some(delegation.id.clone()),
        delegated_by: Some(delegation.delegator.clone()),
    }
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
            Some(AgentState::Revoked | AgentState::Retired) => {
                return deny(DenialReason::AgentRevoked)
            }
            Some(AgentState::Suspended) => return deny(DenialReason::AgentSuspended),
            Some(AgentState::Created) | None => return deny(DenialReason::UnknownPrincipal),
        }
    }

    for rule in &policy.rules {
        if &rule.capability == capability && condition_matches(&rule.condition, principal) {
            return allow(
                GrantedCapability {
                    capability: capability.clone(),
                    policy_id: policy.id.clone(),
                    tenant_id: tenant.tenant_id.clone(),
                    principal_id: principal.id.clone(),
                    principal_kind: principal.kind.clone(),
                    authority: AuthorityBasis::Claim,
                    claim_basis: claim_basis(&rule.condition),
                    delegation_id: None,
                    delegated_by: None,
                },
                None,
                None,
                claim_basis(&rule.condition),
            );
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
        return allow(
            delegated_grant(policy, principal, tenant, delegation, capability),
            None,
            None,
            vec!["delegation".to_string()],
        );
    }

    deny(DenialReason::CapabilityNotGranted)
}

pub fn evaluate_authorization_request(
    policy: Option<&Policy>,
    principal: Option<&Principal>,
    tenant: Option<&TenantContext>,
    delegation: Option<&Delegation>,
    request: &AuthorizationRequest,
    resource_attributes: Option<&ResourceAttributes>,
    now: i64,
) -> AuthorizationDecision {
    let policy = match policy {
        Some(policy) => policy,
        None => return deny_for(request, DenialReason::PolicyNotFound, None),
    };
    let principal = match principal {
        Some(principal) => principal,
        None => return deny_for(request, DenialReason::UnknownPrincipal, Some(policy)),
    };
    let tenant = match tenant {
        Some(tenant) => tenant,
        None => return deny_for(request, DenialReason::UnknownTenant, Some(policy)),
    };

    if principal.id != request.principal
        || principal.tenant_id != tenant.tenant_id
        || tenant.tenant_id != request.tenant
        || policy.id != tenant.policy_id
    {
        return deny_for(request, DenialReason::TenantMismatch, Some(policy));
    }

    if let Some(resource) = &request.resource {
        let resolved_tenant = resource_attributes
            .and_then(|attrs| attrs.tenant_id.as_ref())
            .unwrap_or(&resource.tenant_id);
        if resolved_tenant != &tenant.tenant_id {
            return deny_for(request, DenialReason::TenantMismatch, Some(policy));
        }
    }

    if principal.kind == PrincipalKind::Agent {
        match principal.agent_state {
            Some(AgentState::Active) => {}
            Some(AgentState::Revoked | AgentState::Retired) => {
                return deny_for(request, DenialReason::AgentRevoked, Some(policy))
            }
            Some(AgentState::Suspended) => {
                return deny_for(request, DenialReason::AgentSuspended, Some(policy))
            }
            Some(AgentState::Created) | None => {
                return deny_for(request, DenialReason::UnknownPrincipal, Some(policy))
            }
        }
    }

    for (index, rule) in policy.rules.iter().enumerate() {
        if rule.capability != request.capability {
            continue;
        }
        if rule
            .action
            .as_ref()
            .is_some_and(|action| action != &request.action)
        {
            continue;
        }
        if let Some(selector) = &rule.resource {
            let Some(resource) = &request.resource else {
                continue;
            };
            if !selector.matches(resource) {
                continue;
            }
        }
        if !condition_matches_with_resource(&rule.condition, principal, resource_attributes) {
            continue;
        }
        let matched = vec![format!("rule:{}", index)];
        if rule.effect == Effect::Deny {
            return AuthorizationDecision::Deny {
                reason: DenialReason::CapabilityNotGranted,
                capability: Some(request.capability.clone()),
                resource: request.resource.clone(),
                action: Some(request.action.clone()),
                policy_id: Some(policy.id.clone()),
                matched_rules: matched,
                audit_event_id: None,
            };
        }
        return allow(
            GrantedCapability {
                capability: request.capability.clone(),
                policy_id: policy.id.clone(),
                tenant_id: tenant.tenant_id.clone(),
                principal_id: principal.id.clone(),
                principal_kind: principal.kind.clone(),
                authority: AuthorityBasis::Claim,
                claim_basis: claim_basis(&rule.condition),
                delegation_id: None,
                delegated_by: None,
            },
            request.resource.clone(),
            Some(request.action.clone()),
            matched,
        );
    }

    if principal.kind == PrincipalKind::Agent {
        let delegation = match delegation {
            Some(delegation) => delegation,
            None => return deny_for(request, DenialReason::CapabilityNotGranted, Some(policy)),
        };
        if delegation.tenant_id != tenant.tenant_id || delegation.delegate != principal.id {
            return deny_for(request, DenialReason::InvalidDelegation, Some(policy));
        }
        if delegation.revoked_at.is_some() {
            return deny_for(request, DenialReason::RevokedDelegation, Some(policy));
        }
        if !delegation.is_valid_at(now) {
            return deny_for(request, DenialReason::ExpiredDelegation, Some(policy));
        }
        if !delegation
            .capabilities
            .iter()
            .any(|capability| capability == &request.capability)
        {
            return deny_for(request, DenialReason::CapabilityNotGranted, Some(policy));
        }
        return allow(
            delegated_grant(policy, principal, tenant, delegation, &request.capability),
            request.resource.clone(),
            Some(request.action.clone()),
            vec!["delegation".to_string()],
        );
    }

    deny_for(request, DenialReason::CapabilityNotGranted, Some(policy))
}

fn deny(reason: DenialReason) -> AuthorizationDecision {
    AuthorizationDecision::Deny {
        reason,
        capability: None,
        resource: None,
        action: None,
        policy_id: None,
        matched_rules: Vec::new(),
        audit_event_id: None,
    }
}

fn deny_for(
    request: &AuthorizationRequest,
    reason: DenialReason,
    policy: Option<&Policy>,
) -> AuthorizationDecision {
    AuthorizationDecision::Deny {
        reason,
        capability: Some(request.capability.clone()),
        resource: request.resource.clone(),
        action: Some(request.action.clone()),
        policy_id: policy.map(|policy| policy.id.clone()),
        matched_rules: Vec::new(),
        audit_event_id: None,
    }
}

fn allow(
    grant: GrantedCapability,
    resource: Option<crate::policy::ResourceRef>,
    action: Option<Action>,
    matched_rules: Vec<String>,
) -> AuthorizationDecision {
    AuthorizationDecision::Allow {
        grant,
        resource,
        action,
        matched_rules,
        audit_event_id: None,
    }
}

fn condition_matches(condition: &Condition, principal: &Principal) -> bool {
    condition_matches_with_resource(condition, principal, None)
}

fn condition_matches_with_resource(
    condition: &Condition,
    principal: &Principal,
    resource: Option<&ResourceAttributes>,
) -> bool {
    match condition {
        Condition::Always => true,
        Condition::All(conditions) => conditions
            .iter()
            .all(|condition| condition_matches_with_resource(condition, principal, resource)),
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
        Condition::TenantCurrent => resource
            .and_then(|resource| resource.tenant_id.as_ref())
            .map(|tenant| tenant == &principal.tenant_id)
            .unwrap_or(false),
        Condition::ResourceAttributeEquals { key, value } => resource
            .and_then(|resource| resource.values.get(key))
            .map(|actual| actual == value)
            .unwrap_or(false),
        Condition::ResourceAttributeIn { key, values } => resource
            .and_then(|resource| resource.values.get(key))
            .map(|actual| values.contains(actual))
            .unwrap_or(false),
        Condition::RelationshipEquals {
            resource_attribute,
            principal: principal_attribute,
        } => {
            let Some(left) = resource.and_then(|resource| resource.values.get(resource_attribute))
            else {
                return false;
            };
            principal_attribute_value(principal, principal_attribute)
                .map(|right| left == &right)
                .unwrap_or(false)
        }
    }
}

fn claim_basis(condition: &Condition) -> Vec<String> {
    match condition {
        Condition::Always => vec!["always".to_string()],
        Condition::All(conditions) => conditions.iter().flat_map(claim_basis).collect::<Vec<_>>(),
        Condition::ClaimEquals { key, .. } | Condition::ClaimIn { key, .. } => vec![key.clone()],
        Condition::TimeBound { .. } => vec!["time".to_string()],
        Condition::TenantCurrent => vec!["tenant=current".to_string()],
        Condition::ResourceAttributeEquals { key, .. }
        | Condition::ResourceAttributeIn { key, .. } => {
            vec![format!("resource.{}", key)]
        }
        Condition::RelationshipEquals {
            resource_attribute, ..
        } => vec![format!("resource.{}", resource_attribute)],
    }
}

fn principal_attribute_value(
    principal: &Principal,
    attribute: &PrincipalAttribute,
) -> Option<appport_auth_mesh_contract::ClaimValue> {
    match attribute {
        PrincipalAttribute::Id => Some(appport_auth_mesh_contract::ClaimValue::String(
            principal.id.to_string(),
        )),
        PrincipalAttribute::Tenant => Some(appport_auth_mesh_contract::ClaimValue::String(
            principal.tenant_id.to_string(),
        )),
        PrincipalAttribute::Claim(key) => principal.claims.values.get(key).cloned(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use appport_auth_mesh_contract::{
        ClaimValue, Claims, ContractVersion, Principal, PrincipalId, PrincipalKind, TenantContext,
    };

    use crate::{
        evaluator::{evaluate, evaluate_authorization_request},
        policy::{
            Action, AuthorizationContext, AuthorizationRequest, Condition, DenialReason, Effect,
            Policy, PrincipalAttribute, ResourceAttributes, ResourceRef, ResourceSelector, Rule,
        },
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
            rules: vec![Rule::allow(
                "billing.charge",
                Condition::ClaimEquals {
                    key: "role".to_string(),
                    value: ClaimValue::Enum("admin".to_string()),
                },
            )],
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
            rules: vec![Rule::allow(
                "storage.read",
                Condition::TimeBound {
                    start: 0,
                    end: i64::MAX,
                },
            )],
        };

        let err = evaluate(&policy, &principal, &tenant).expect_err("tenant mismatch must fail");
        assert_eq!(
            err.message,
            "principal tenant does not match tenant context"
        );
    }

    #[test]
    fn resource_requests_enforce_tenant_claims_and_relationships() {
        let mut claims = HashMap::new();
        claims.insert("role".to_string(), ClaimValue::Enum("admin".to_string()));
        claims.insert(
            "department".to_string(),
            ClaimValue::String("finance".to_string()),
        );
        let principal = Principal {
            id: PrincipalId("user-1".to_string()),
            kind: PrincipalKind::Human,
            tenant_id: "acme".into(),
            claims: Claims { values: claims },
            version: ContractVersion { major: 1, minor: 0 },
            agent_state: None,
        };
        let tenant = TenantContext {
            tenant_id: "acme".into(),
            namespace: "acme".to_string(),
            policy_id: "p1".into(),
            storage_root_id: "root-a".into(),
        };
        let policy = Policy {
            id: "p1".into(),
            rules: vec![Rule {
                capability: "invoice.update".into(),
                condition: Condition::All(vec![
                    Condition::TenantCurrent,
                    Condition::ClaimIn {
                        key: "role".to_string(),
                        values: vec![
                            ClaimValue::Enum("owner".to_string()),
                            ClaimValue::Enum("admin".to_string()),
                        ],
                    },
                    Condition::RelationshipEquals {
                        resource_attribute: "department".to_string(),
                        principal: PrincipalAttribute::Claim("department".to_string()),
                    },
                ]),
                resource: Some(ResourceSelector::any("invoice")),
                action: Some(Action("update".to_string())),
                effect: Effect::Allow,
            }],
        };
        let request = AuthorizationRequest {
            principal: principal.id.clone(),
            tenant: tenant.tenant_id.clone(),
            capability: "invoice.update".into(),
            action: "update".into(),
            resource: Some(ResourceRef::new("invoice", "8472", "acme")),
            context: AuthorizationContext::default(),
        };
        let attributes = ResourceAttributes::new()
            .with_tenant("acme")
            .with_value("department", ClaimValue::String("finance".to_string()));

        let decision = evaluate_authorization_request(
            Some(&policy),
            Some(&principal),
            Some(&tenant),
            None,
            &request,
            Some(&attributes),
            0,
        );
        assert!(decision.is_allowed());

        let globex_attributes = ResourceAttributes::new()
            .with_tenant("globex")
            .with_value("department", ClaimValue::String("finance".to_string()));
        let denied = evaluate_authorization_request(
            Some(&policy),
            Some(&principal),
            Some(&tenant),
            None,
            &request,
            Some(&globex_attributes),
            0,
        );
        assert_eq!(denied.denial_reason(), Some(DenialReason::TenantMismatch));
    }
}
