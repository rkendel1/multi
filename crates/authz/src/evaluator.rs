use appport_auth_mesh_contract::{
    AgentState, Capability, ClaimValue, Delegation, Principal, PrincipalKind, ResourceScope,
    TenantContext,
};

use crate::policy::{
    Action, AuthorityBasis, AuthorizationDecision, AuthorizationRequest, CapabilityEnvelope,
    Condition, ConditionEvidence, ConditionResult, DenialReason, Effect, GrantedCapability, Policy,
    PrincipalAttribute, ResourceAttributes,
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
                delegation_chain: Vec::new(),
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
        delegation_chain: delegation_chain(delegation),
        delegated_by: Some(delegation.delegator.clone()),
    }
}

fn delegation_chain(delegation: &Delegation) -> Vec<appport_auth_mesh_contract::DelegationId> {
    let mut chain = delegation.chain.clone();
    chain.push(delegation.id.clone());
    chain
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
        if &rule.capability == capability {
            let (matches, conditions) = evaluate_condition(&rule.condition, principal, None);
            if !matches {
                continue;
            }
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
                    delegation_chain: Vec::new(),
                    delegated_by: None,
                },
                None,
                None,
                claim_basis(&rule.condition),
                conditions,
            );
        }
    }

    if principal.kind == PrincipalKind::Agent {
        let delegation = match delegation {
            Some(delegation) => delegation,
            None => return deny(DenialReason::DelegationMissing),
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
            return deny(DenialReason::DelegationMissing);
        }
        return allow(
            delegated_grant(policy, principal, tenant, delegation, capability),
            None,
            None,
            vec!["delegation".to_string()],
            Vec::new(),
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

    let mut failed_conditions = None;
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
        let (conditions_match, conditions) =
            evaluate_condition(&rule.condition, principal, resource_attributes);
        if !conditions_match {
            failed_conditions = Some(conditions);
            continue;
        }
        let matched = vec![format!("rule:{}", index)];
        if rule.effect == Effect::Deny {
            return AuthorizationDecision::Deny {
                reason: DenialReason::PolicyDenied,
                capability: Some(request.capability.clone()),
                resource: request.resource.clone(),
                action: Some(request.action.clone()),
                policy_id: Some(policy.id.clone()),
                matched_rules: matched,
                conditions,
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
                delegation_chain: Vec::new(),
                delegated_by: None,
            },
            request.resource.clone(),
            Some(request.action.clone()),
            matched,
            conditions,
        );
    }

    if principal.kind == PrincipalKind::Agent {
        let delegation = match delegation {
            Some(delegation) => delegation,
            None => return deny_for(request, DenialReason::DelegationMissing, Some(policy)),
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
            return deny_for(request, DenialReason::DelegationMissing, Some(policy));
        }
        if !delegation_scope_matches(&delegation.resource_scope, request, resource_attributes) {
            return deny_for(request, DenialReason::DelegationScopeDenied, Some(policy));
        }
        return allow(
            delegated_grant(policy, principal, tenant, delegation, &request.capability),
            request.resource.clone(),
            Some(request.action.clone()),
            vec!["delegation".to_string()],
            Vec::new(),
        );
    }

    if let Some(conditions) = failed_conditions {
        deny_for_with_conditions(
            request,
            DenialReason::ConditionFailed,
            Some(policy),
            conditions,
        )
    } else {
        deny_for(request, DenialReason::CapabilityNotGranted, Some(policy))
    }
}

fn deny(reason: DenialReason) -> AuthorizationDecision {
    AuthorizationDecision::Deny {
        reason,
        capability: None,
        resource: None,
        action: None,
        policy_id: None,
        matched_rules: Vec::new(),
        conditions: Vec::new(),
        audit_event_id: None,
    }
}

fn deny_for(
    request: &AuthorizationRequest,
    reason: DenialReason,
    policy: Option<&Policy>,
) -> AuthorizationDecision {
    deny_for_with_conditions(request, reason, policy, Vec::new())
}

fn deny_for_with_conditions(
    request: &AuthorizationRequest,
    reason: DenialReason,
    policy: Option<&Policy>,
    conditions: Vec<ConditionEvidence>,
) -> AuthorizationDecision {
    AuthorizationDecision::Deny {
        reason,
        capability: Some(request.capability.clone()),
        resource: request.resource.clone(),
        action: Some(request.action.clone()),
        policy_id: policy.map(|policy| policy.id.clone()),
        matched_rules: Vec::new(),
        conditions,
        audit_event_id: None,
    }
}

fn allow(
    grant: GrantedCapability,
    resource: Option<crate::policy::ResourceRef>,
    action: Option<Action>,
    matched_rules: Vec<String>,
    conditions: Vec<ConditionEvidence>,
) -> AuthorizationDecision {
    AuthorizationDecision::Allow {
        grant,
        resource,
        action,
        matched_rules,
        conditions,
        audit_event_id: None,
    }
}

fn delegation_scope_matches(
    scope: &ResourceScope,
    request: &AuthorizationRequest,
    resource_attributes: Option<&ResourceAttributes>,
) -> bool {
    if scope.is_unconstrained() {
        return true;
    }
    let Some(resource) = &request.resource else {
        return false;
    };
    if let Some(resource_type) = &scope.resource_type {
        if resource_type != &resource.resource_type {
            return false;
        }
    }
    if let Some(resource_id) = &scope.resource_id {
        if resource_id != "*" && resource_id != &resource.resource_id {
            return false;
        }
    }
    scope.attributes.iter().all(|(key, expected)| {
        if key == "tenant" || key == "tenant_id" {
            return matches_tenant(expected, &resource.tenant_id.0);
        }
        resource_attributes.and_then(|attributes| attributes.values.get(key)) == Some(expected)
    })
}

fn matches_tenant(value: &ClaimValue, tenant_id: &str) -> bool {
    match value {
        ClaimValue::Enum(value) | ClaimValue::String(value) => value == tenant_id,
        _ => false,
    }
}

fn condition_matches(condition: &Condition, principal: &Principal) -> bool {
    evaluate_condition(condition, principal, None).0
}

fn evaluate_condition(
    condition: &Condition,
    principal: &Principal,
    resource: Option<&ResourceAttributes>,
) -> (bool, Vec<ConditionEvidence>) {
    match condition {
        Condition::Always => (true, vec![condition_evidence("always", true, None)]),
        Condition::All(conditions) => {
            let mut all_match = true;
            let mut evidence = Vec::new();
            for condition in conditions {
                let (matches, mut condition_evidence) =
                    evaluate_condition(condition, principal, resource);
                all_match &= matches;
                evidence.append(&mut condition_evidence);
            }
            (all_match, evidence)
        }
        Condition::ClaimEquals { key, value } => {
            let matches = principal.claims.values.get(key) == Some(value);
            (
                matches,
                vec![condition_evidence(
                    format!("claim.{} == {}", key, claim_value_text(value)),
                    matches,
                    Some(claim_fact(key, principal.claims.values.contains_key(key))),
                )],
            )
        }
        Condition::ClaimIn { key, values } => {
            let present = principal.claims.values.get(key);
            let matches = present.map(|v| values.contains(v)).unwrap_or(false);
            (
                matches,
                vec![condition_evidence(
                    format!(
                        "claim.{} in [{}]",
                        key,
                        values
                            .iter()
                            .map(claim_value_text)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    matches,
                    Some(claim_fact(key, present.is_some())),
                )],
            )
        }
        Condition::TimeBound { start, end } => {
            let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(v) => v.as_secs() as i64,
                Err(_) => {
                    return (
                        false,
                        vec![condition_evidence(
                            format!("time between {} and {}", start, end),
                            false,
                            Some("time unavailable".to_string()),
                        )],
                    )
                }
            };
            let matches = now >= *start && now <= *end;
            (
                matches,
                vec![condition_evidence(
                    format!("time between {} and {}", start, end),
                    matches,
                    Some("system time evaluated".to_string()),
                )],
            )
        }
        Condition::TenantCurrent => {
            let resource_tenant = resource.and_then(|resource| resource.tenant_id.as_ref());
            let matches = resource_tenant
                .map(|tenant| tenant == &principal.tenant_id)
                .unwrap_or(false);
            (
                matches,
                vec![condition_evidence(
                    "tenant=current",
                    matches,
                    Some(match resource_tenant {
                        Some(_) if matches => "resource tenant matched current tenant".to_string(),
                        Some(_) => "resource tenant did not match current tenant".to_string(),
                        None => "resource tenant unavailable".to_string(),
                    }),
                )],
            )
        }
        Condition::ResourceAttributeEquals { key, value } => {
            let actual = resource.and_then(|resource| resource.values.get(key));
            let matches = actual.map(|actual| actual == value).unwrap_or(false);
            (
                matches,
                vec![condition_evidence(
                    format!("resource.{} == {}", key, claim_value_text(value)),
                    matches,
                    Some(resource_fact(key, actual.is_some())),
                )],
            )
        }
        Condition::ResourceAttributeIn { key, values } => {
            let actual = resource.and_then(|resource| resource.values.get(key));
            let matches = actual
                .map(|actual| values.contains(actual))
                .unwrap_or(false);
            (
                matches,
                vec![condition_evidence(
                    format!(
                        "resource.{} in [{}]",
                        key,
                        values
                            .iter()
                            .map(claim_value_text)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    matches,
                    Some(resource_fact(key, actual.is_some())),
                )],
            )
        }
        Condition::RelationshipEquals {
            resource_attribute,
            principal: principal_attribute,
        } => {
            let Some(left) = resource.and_then(|resource| resource.values.get(resource_attribute))
            else {
                return (
                    false,
                    vec![condition_evidence(
                        format!(
                            "resource.{} == principal.{}",
                            resource_attribute,
                            principal_attribute_name(principal_attribute)
                        ),
                        false,
                        Some(resource_fact(resource_attribute, false)),
                    )],
                );
            };
            let right = principal_attribute_value(principal, principal_attribute);
            let matches = right.map(|right| left == &right).unwrap_or(false);
            (
                matches,
                vec![condition_evidence(
                    format!(
                        "resource.{} == principal.{}",
                        resource_attribute,
                        principal_attribute_name(principal_attribute)
                    ),
                    matches,
                    Some(if matches {
                        "relationship matched".to_string()
                    } else {
                        "relationship did not match".to_string()
                    }),
                )],
            )
        }
    }
}

fn condition_evidence(
    condition: impl Into<String>,
    passed: bool,
    fact: Option<String>,
) -> ConditionEvidence {
    ConditionEvidence {
        condition: condition.into(),
        result: if passed {
            ConditionResult::Pass
        } else {
            ConditionResult::Fail
        },
        fact,
    }
}

fn claim_fact(key: &str, present: bool) -> String {
    if present {
        format!("claim.{} present", key)
    } else {
        format!("claim.{} missing", key)
    }
}

fn resource_fact(key: &str, present: bool) -> String {
    if present {
        format!("resource.{} present", key)
    } else {
        format!("resource.{} missing", key)
    }
}

fn principal_attribute_name(attribute: &PrincipalAttribute) -> String {
    match attribute {
        PrincipalAttribute::Id => "id".to_string(),
        PrincipalAttribute::Tenant => "tenant".to_string(),
        PrincipalAttribute::Claim(key) => format!("claim.{}", key),
    }
}

fn claim_value_text(value: &appport_auth_mesh_contract::ClaimValue) -> String {
    match value {
        appport_auth_mesh_contract::ClaimValue::Enum(value)
        | appport_auth_mesh_contract::ClaimValue::String(value) => value.clone(),
        appport_auth_mesh_contract::ClaimValue::Integer(value) => value.to_string(),
        appport_auth_mesh_contract::ClaimValue::Boolean(value) => value.to_string(),
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
            Action, AuthorizationContext, AuthorizationRequest, Condition, ConditionResult,
            DenialReason, Effect, Policy, PrincipalAttribute, ResourceAttributes, ResourceRef,
            ResourceSelector, Rule,
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

        let mismatch_attributes = ResourceAttributes::new()
            .with_tenant("acme")
            .with_value("department", ClaimValue::String("legal".to_string()));
        let condition_denied = evaluate_authorization_request(
            Some(&policy),
            Some(&principal),
            Some(&tenant),
            None,
            &request,
            Some(&mismatch_attributes),
            0,
        );
        assert_eq!(
            condition_denied.denial_reason(),
            Some(DenialReason::ConditionFailed)
        );
        let conditions = condition_denied.conditions();
        assert_eq!(conditions.len(), 3);
        assert_eq!(conditions[0].result, ConditionResult::Pass);
        assert_eq!(conditions[1].result, ConditionResult::Pass);
        assert_eq!(conditions[2].result, ConditionResult::Fail);
        assert_eq!(
            conditions[2].condition,
            "resource.department == principal.claim.department"
        );
    }
}
